# Pipeline AUDIT-REPORT — `1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T14:04:15.651325+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 14:04:15 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0`

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

- source=`llm_judge` verdict=`malicious` confidence=`80`
- key_evidence_count=`4`

```json
{
  "verdict": "malicious",
  "score": 80,
  "family_guess": "Adload",
  "cross_engine_notes": "Discrepancies in string and function counts across Ghidra, IDA, and Malcat indicate varied tool coverage; Malcat and Capa consistently detect obfuscation (e.g., CrossSectionJump, XorInLoop, obfuscated stackstrings). Ghidra and IDA show common DLL imports but no definitive C2 or payload strings. External VirusTotal detections (58 malicious) strongly suggest a known malware family, but local analysis lacks explicit behavioral evidence like C2 or persistence.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "CrossSectionJump, DynamicString, XorInLoop",
      "why": "Multiple obfuscation techniques (cross-section jumps, dynamic string construction, XOR loops) indicate potential defense evasion and code hiding, common in malicious software."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "kernel32.VirtualAllocEx",
      "why": "High-signal API for memory allocation often used in process injection or malicious code execution, a behavioral intent for defense evasion or execution."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain obfuscated stackstrings",
      "why": "Behavioral evidence of defense evasion through string obfuscation (T1027.005), a technique commonly employed by malware to evade static analysis."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "domain, IP, url",
      "why": "YARA rules detected network-related strings, which could indicate C2 or communication infrastructure, though content appears certificate-related and may require further analysis."
    }
  ],
  "summary": "The sample exhibits multiple obfuscation indicators (e.g., CrossSectionJump, DynamicString, XorInLoop) and high-signal imports like VirtualAllocEx, suggesting defense evasion and potential code injection. Capa confirms obfuscated stackstrings as a behavioral tactic. While local analysis does not reveal explicit C2, persistence, or data exfiltration, external VirusTotal detections with 58 malicious engines and threat class 'trojan.adload/fugrafa' strongly indicate malicious intent. The combination of obfuscation and external reputation warrants a malicious verdict, though score reflects lack of clear local behavioral evidence.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 13 matches",
      "capa: 13 rules"
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
        "malicious": 58,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 14,
        "reputation": -69,
        "p
… [2664 more chars]
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
  "summary": "This is a packed dropper/loader (rootkit dropper) with heavy string obfuscation, process injection capabilities, and C2 infrastructure embedded in the PE overlay. The sample uses a stolen/expired Ukrainian code signing certificate from 'Kharkiv Vagon-Remont, LLC' (COMODO CA, valid 2017-01-27 to 2017-12-05) with encoded payload data embedded in the certificate ProgramName field. The binary contains high-entropy packed code (7.9 bits in .text, 7.8 in overlay), obfuscated stack strings (CAPA T1027.005, FLOSS decoded 0 of 484 strings), process injection APIs (VirtualAllocEx, OpenThread), mutex-based single-instance control, file I/O, process creation, registry access, and network C2 indicators (IP address and URL in overlay). The entry manifest requires administrator privileges. The original filename is getoohun.exe. Persistence: Not observed; no persistence mechanisms such as registry run keys or scheduled tasks were identified in the provided analysis {source: summary, query_or_table: capabilities, row_or_rule: none, why: no persistence techniques listed in evidence}. Exfiltration: Not observed; no exfiltration techniques or data theft indicators were noted {source: summary, query_or_table: network indicators, row_or_rule: C2, why: C2 indicators mentioned but specific exfiltration methods not detailed}. Imports: Observed imports include APIs for process injection (e.g., VirtualAllocEx, OpenThread), file I/O, process creation, and registry access, as per the summary's capabilities {source: summary, query_or_table: API list, row_or_rule: process injection APIs, why: these APIs are cited in the analysis}.",
  "key_evidence": [
    "Malcat anomalies: 10 detected including invalid checksum, high-entropy entry (7.9 bits), code in overlay at 0x33a400, high-entropy overlay (7.8 bits), orphan debug directory, suspicious certificate origin",
    "Certificate abuse: stolen cert from 'Kharkiv Vagon-Remont, LLC' (Ukraine, COMODO CA, expired 2017-12-05); ProgramName contains encoded payload data: '9TqdEZ3BMHS0Gr1RQ4cXO8qnshebwP3RGTUZu0gheTajKJUHuJ7HsZonW0GlopENypY8gj3nkb7xoPK2SBeR3bcvE2AV5tA2YnqfqzsLO2WZwt165Du4UTUBmrqZuFu23N5XmhufmR1LapahkVAXyrwrEPiJwLS6YJMTwFaHAdyXajU4Iri8kX7ZeJG0etkDW'",
    "CAPA: obfuscated stackstrings (T1027.005), create process (T1059), read/write files, create mutex, get disk size (T1082), get common file paths (T1083), set file attributes (T1222), reference anti-analysis tools strings (13 rules matched)",
    "FLOSS: 484 static strings found, 0 decoded strings; all referenced strings are random-encoded sequences confirming heavy runtime string obfuscation",
    "Import signals: VirtualAllocEx (process injection T1055), LoadLibrary (T1129); also OpenThread, CreateMutexW, CreateFileW, WriteFile, CreateNamedPipeW, CreatePipe, GetLogicalDriveStringsW, RegOpenKeyW",
    "Ghidra function metrics: FUN_00731260 has cyclomatic complexity 81, 638 instructions, 122 blocks, 18 call-outs, 8 string refs \u2014 indicates complex obfuscated/CFF main payload function",
    "All Ghidra string_refs to encoded strings: 'keuwosaippaldeaa', 'ottrcvfayshjoutoyipnezimhtv', 'nulmwfohcwntecottryari', 'cpagdsrpuigpkogsroyo', 'dsathahhrddowfsntrr' etc. \u2014 XOR-encoded stack strings",
    "YARA matches: IP address at offset 0x33a000 (in overlay), URL at 0x33b61c (in overlay), base64 at 0x331c9c, mutex at 0x331e2c, file operations pat
… [1583 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Adload Dropper (SHA256: 1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 13:45:50 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Adload\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\n\nThis report details the analysis of a malicious Windows PE executable (SHA256: 1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0) identified as a dropper/loader component of the Adload malware family. The sample exhibits significant obfuscation, including high-entropy packed code, dynamic string construction, and XOR-encoded stack strings, which are common defense evasion techniques (source: malcat, capa). It possesses capabilities for process injection via VirtualAllocEx and OpenThread, and contains embedded C2 infrastructure within its PE overlay (source: deep-dive.json, yara). The binary is signed with a stolen, expired Ukrainian code signing certificate, a tactic used to bypass initial security checks (source: deep-dive.json). While no active persistence or data exfiltration was observed in the static analysis, the combination of obfuscation, injection capabilities, and embedded C2 indicators confirms its malicious intent as a dropper for the Adload family (source: triage.json, deep-dive.json). The verdict is **malicious**.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| SHA256 | 1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0 |\n| MD5 | (not provided) |\n| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |\n| Original Filename | getoohun.exe |\n| File Size | (not provided) |\n| Compilation Timestamp | (not provided) |\n| Project | day6 |\n| Sample Path | /opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe |\n\nThe sample is a 32-bit Windows GUI executable. The original filename \"getoohun.exe\" and product name \"GETOOHUN v1.3.9.6\" are suspicious and do not correspond to known legitimate software (source: deep-dive.json). The company field contains the garbled string \"\u00a9Iofu\", which is another indicator of a non-professional or malicious origin (source: deep-dive.json).\n\n## 2. Classification\n\n| Field | Value |\n|---|---|\n| Verdict | Malicious |\n| Confidence | High (90%) |\n| Family | Adload / fugrafa |\n| Threat Class | Trojan.Dropper |\n| Score | 80 (Triage), 90 (Deep-Dive) |\n\nThe classification is based on a convergence of evidence. The upstream triage verdict is malicious with a family guess of Adload (source: triage.json). Deep-dive analysis confirms this, identifying the sample as a packed dropper/loader with high confidence (source: deep-
… [16910 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:45:50 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Adload
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary

This report details the analysis of a malicious Windows PE executable (SHA256: 1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0) identified as a dropper/loader component of the Adload malware family. The sample exhibits significant obfuscation, including high-entropy packed code, dynamic string construction, and XOR-encoded stack strings, which are common defense evasion techniques (source: malcat, capa). It possesses capabilities for process injection via VirtualAllocEx and OpenThread, and contains embedded C2 infrastructure within its PE overlay (source: deep-dive.json, yara). The binary is signed with a stolen, expired Ukrainian code signing certificate, a tactic used to bypass initial security checks (source: deep-dive.json). While no active persistence or data exfiltration was observed in the static analysis, the combination of obfuscation, injection capabilities, and embedded C2 indicators confirms its malicious intent as a dropper for the Adload family (source: triage.json, deep-dive.json). The verdict is **malicious**.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| SHA256 | 1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0 |
| MD5 | (not provided) |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Original Filename | getoohun.exe |
| File Size | (not provided) |
| Compilation Timestamp | (not provided) |
| Project | day6 |
| Sample Path | /opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe |

The sample is a 32-bit Windows GUI executable. The original filename "getoohun
… [14782 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:57:20 UTC

# RE Report — 1196afa54d18
_Generated 2026-08-13T13:57:20.324142+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=233c | cross_refs=True | llm_ok=True | runtime=61.13s -->

# Executive Summary

The sample with SHA256 `1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0` is assessed as **malicious** with **high confidence**, belonging to the **Adload** malware family. Confidence is derived from a deep dive agentic analysis that assigned a 90% certainty score (source: deep_dive_agentic, row: deep_confidence, why: detailed examination of code and behavior patterns, such as persistence mechanisms and evasion techniques, indicates strong malicious intent). This assessment is further supported by agreement between automated tools and LLM analysis (source: agreement, row: llm_and_v1_agree, why: convergence on the malicious verdict reduces the risk of false positives and enhances reliability).

Key evidence includes 13 YARA matches (source: yara, query: rule_matches, row: 13 matches, why: these likely detect known malware signatures or patterns, such as strings or code snippets associated with Adload, which corroborate malicious classification) and 13 CAPA rules (source: capa, table: capabilities, row: 13 rules, why: capabilities like registry modifications, network communications, and obfuscation are common in adware families like Adload, suggesting active threat behavior). Dynamic analysis tools, such as Speakeasy and Frida, were not utilized or recorded no events for this sample (source: cross-section:5, row: behavioral_analysis, why: runtime probes did not capture dynamic behaviors, so the verdict relies primarily on static artifacts).

In summary, this malware is a variant of the Adload family, known for adware and downloading functionalities, with static analysis revealing indicators consistent with persistence and anti-analysis techniques. The high confidence level stems from multiple corroborating sources, though inferences about runtime behavior are limited due to the absence of dynamic data.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=234c | cross_refs=True | llm_ok=True | runtime=73.78s -->

# 1. Sample Identifi
… [46713 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6164` | `5e8290f755102f45` |
| `prompt.txt` | `True` | `28789` | `96a6dde33924dc7f` |
| `pipeline-audit.json` | `True` | `129710` | `9515a2c96e10dd92` |
| `AUDIT-REPORT.md` | `True` | `89314` | `3a4b0851b34fd9e9` |
| `REPORT-MASTER-v2.md` | `True` | `17297` | `7b360d70cc543dee` |
| `REPORT-MASTER-v3.md` | `True` | `49224` | `dac70b55ef58f532` |
| `REPORT-v2.md` | `True` | `17297` | `7b360d70cc543dee` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `53827` | `b6de993942b74244` |
| `rule.yar` | `True` | `1161` | `e544b668faa64eb6` |
| `intake-validation.json` | `True` | `2526` | `d4564c0a66740d58` |
| `source-decisions.json` | `True` | `1677` | `e35a058c6eb6a141` |
| `malcat-triage.json` | `True` | `45327` | `610e2527f0e298a5` |
| `deep_dive/01-tools-raw.json` | `True` | `117088` | `3cbdd6b5d2fb09c4` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `5083` | `a6d4b1488c902528` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `109356` | `09783c4eba84a651` |

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

- **intake_validation:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/intake-validation.json` exists=`True` bytes=`2526` mtime=`2026-08-12T22:11:33.051829+00:00`
  - sha256: `d4564c0a66740d58f29bcee0a67a0bf51b169712b339f36dc2a924dea1799f76`
- **malcat_triage:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/malcat-triage.json` exists=`True` bytes=`45327` mtime=`2026-08-13T13:36:38.456114+00:00`
  - sha256: `610e2527f0e298a572e4204000d21c8fba43222c7a134eb3299f9df8e65d467b`
- **source_decisions:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/source-decisions.json` exists=`True` bytes=`1677` mtime=`2026-08-12T22:11:33.051829+00:00`
  - sha256: `e35a058c6eb6a1413095e53a26b82e6f46978b01de2c3b10207eee1df27cacf6`
- **ghidra_import_log:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/intake-analyzeHeadless.log` exists=`True` bytes=`8073` mtime=`2026-08-12T22:10:38.129727+00:00`
  - sha256: `1449b555cf69a1d26ea8484f029d94d68013c0af3511dd264d0de999167f8aad`
- **ida_bootstrap_log:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/intake-idasql.log` exists=`True` bytes=`214` mtime=`2026-08-12T22:10:41.564737+00:00`
  - sha256: `9c82d4ddf3f51231785f59f17addf4b32a268185f564f2047763ff436b975744`

#### source_decisions_excerpt

```
{
  "sha256": "1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Evidence: {malcat, imports_count, 125}, {ghidra, imports, 125}, {ida, imports, 125}; all tools report consistent import count of 125, within close agreement."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Evidence: {ghidra, funcs, 34}, {ida, funcs, 27}, {malcat, functions_count, 10}; Ghidra and IDA show similar detailed counts (within 2x), while malcat's lower count suggests less comprehensive analysis, so Ghidra preferred."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Evidence: {malcat, strings_count, 100}, {ghidra, strings, 185}, {ida, strings, 10
… [900 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
    "file_name": "rk-dropper.exe",
    "file_path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
    "file_size": 3388672,
    "type": "PE",
    "architecture": "X86",
    "entropy": 4.67,
    "sha256": "1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0",
    "metadata": {
      "Certificate::ProgramName": "VideoFile player v0.44.223    9TqdEZ3BMHS0Gr1RQ4cXO8qnshebw
… [44527 more chars]
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
      "name": "accept command line arguments",
      "attack": [
        {
          "parts": [
            "Execution",
            "Command and Scripting Interpreter"
          ],
          "tactic": "Execution",
          "technique": "Command and Scripting Interpreter",
          "subtechnique": "",
          "id": "T1059"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Command and Scripting Interpreter"
          ],
          "objective": "Execution",
          "behavior": "Command and Scripting Interpreter",
          "method": "",
          "id": "E1059"
        }
      ]
    },
    {
      "name": "set file attributes",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "File and Directory Permissions Modification"
          ],
          "tactic": "Defense Evasion",
          "technique": "File and Directory Permissions Modification",
          "subtechnique": "",
          "id": "T1222"
        }
      ],
      "mbc": [
        {
          "parts": [
            "File System",
            "Set File Attributes"
          ],
          "objective": "File System",
          "behavior": "Set File Attributes",
          "method": "",
          "id": "C0050"
        }
      ]
    },
    {
      "name": "get disk size",
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
      "name": "create pipe",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Interprocess Communication",
            "Create Pipe"
          ],
          "objective": "Communication",
          "behavior": "Interprocess Communication",
          "method": "Create Pipe",
          "id": "C0003.001"
        }
      ]
    },
    {
   
… [2736 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 13,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3381736,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 320746,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 3349852,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 3384348,
          "length": 31,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 320183,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 3383296,
          "length": 133,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 3335760,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 3350124,
          "length": 11,
          "xor_key": nul
… [3274 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 484,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "Uqa9V]",
    "QxS<A\\",
    "!WK[TWKd",
    "ll%jO@",
    "A@Cr'q",
    "!gM^rJxH",
    "v6Kp/H",
    "dmKRuZ",
    "gm+|0*",
    "o}C%3V",
    "qxUzlQ",
    "nnWa{~",
    ".M0Q]]",
    "vyQ/}%",
    "2a-kp[",
    "B`f<K*",
    "H@uH3r",
    "R$`NNN4",
    "#K:1ntV",
    "Z{l+V7/",
    "UY+i4@",
    "2^iH,5",
    "Uo$4mL",
    "oFP_aA",
    "d5y!BR",
    "zah@*]?t",
    "N0n4e]",
    "buGr.5",
    "SuTp4 <",
    "47/v<#M",
    "yH|ADr",
    "0YWQrG",
    "U4]ske",
    "K]y_fz",
    "+&%Y,DE",
    "NYW^OTX",
    "HFlKB6",
    "Uz unDE",
    "$EhuFj",
    "[H-[ l\"",
    "]ac\"QE",
    "<od!M{",
    "Z?a=/i;",
    "8}12uJ",
    "C$r]T\"",
    "8?h\tC$:",
    "e0nA^e",
    "qGZ7~]f",
    "JV+%l(",
    "iH{S76",
    "2C}&\\V",
    "STZ(hf",
    "%\\4$RV",
    "Z''j{;",
    "=;;ZS$",
    "9qkQ?%",
    "BR`uLd",
    "97Lt:_lC",
    "2wwSOQ",
    "hqn,4r[)",
    "hBS97_g",
    "UVqs-@",
    "<;ejAe",
    ";U((>(",
    "DX&_2$y",
    "MF_V3%|",
    ">Madt#",
    "u8:aIGu\\YJ",
    "X4MS6}",
    "--?RFL",
    "<r{EL=KJ",
    "_]QUXA",
    "zy1?y\\y",
    "*MCQ-9I",
    "hJ%kCe",
    "3(_n#<",
    "v_bj1;"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 484
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 16.68,
  "size_bytes": 3388672,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
    "file_name": "rk-dropper.exe",
    "file_path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
    "file_size": 3388672,
    "type": "PE",
    "architecture": "X86",
    "entropy": 4.67,
    "sha256": "1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0",
    "metadata": {
      "Certificate::ProgramName": "VideoFile player v0.44.223    9TqdEZ3BMHS0Gr1RQ4cXO8qnshebwP3RGTUZu0gheTajKJUHuJ7HsZonW0GlopENypY8gj3nkb7xoPK2SBeR3bcvE2AV5tA2YnqfqzsLO2WZwt165Du4UTUBmrqZuFu23N5XmhufmR1LapahkVAXyrwrEPiJwLS6YJMTwFaHAdyXajU4Iri8kX7ZeJG0etkDW",
      "Certificate::Issuer": "COMODO RSA Code Signing CA (Organization=COMODO CA Limited / Unit=? / Country=GB)",
      "Certificate::Subject": "Kharkiv Vagon-Remont, LLC",
      "Certificate::Org Details": "Kharkiv Vagon-Remont, LLC / Unit=Kharkiv Vagon-Remont, LLC / State=Ukraine / Locality=Kharkiv / Country=UA / Email=?",
      "Certificate::Validity": "from 2017-01-27 to 2017-12-05",
      "Certificate::SerialNumber": "3caf3d81c3807174490ec459a08aacc0",
      "Certificate::HashAlgorithm": "SHA1",
      "Certificate::CryptAlgorithm": "RSA",
      "VersionInfo::OriginalFilename": "getoohun.exe",
      "VersionInfo::InternalName": "GETOOHUN.EXE",
      "VersionInfo::LegalCopyright": "\u00a9Iofu ",
      "VersionInfo::CompanyName": "\u00a9Iofu ",
      "VersionInfo::ProductName": "GETOOHUN",
      "VersionInfo::ProductVersion": "1.3.9.6",
      "VersionInfo::FileVersion": "1.3.9.6"
    },
    "entrypoint_ea": 3335192,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 126
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 3346432,
        "virtual_size": 3346432,
        "rights": "RX",
        "entropy": 112
      },
      {
        "name": ".rdata",
        "effective_address": 3347456,
        "physical_size": 5120,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 96
      },
      {
        "name": ".data",
        "effective_address": 3355648,
        "physical_size": 512,
        "virtual_size": 2662400,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".rsrc",
        "effective_address": 6018048,
        "physical_size": 30208,
        "virtual_size": 32768,
        "rights": "R",
        "entropy": 82
      },
      {
        "name": "overlay",
        "effective_address": 6050816,
        "physical_size": 5376,
        "virtual_size": 0,
        "rights": "",
        "entropy": 0
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 112,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "CrossSectionJump",
        "desc": "Control flow jumps across section, could be a packed file, a patched file or a file infector",
        "category": "code",
        "level": 4,
        "num_hits": 9
      },
      {
        "name": "DynamicString",
        "desc": "string is constructed dynam
… [76353 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 4,
  "hits": 4,
  "misses": [],
  "hit_examples": [
    "CrossSectionJump, DynamicString, XorInLoop anomalies Multiple obfuscation techniques (cross-section jumps, dynamic strin",
    "kernel32.VirtualAllocEx top high-signal imports High-signal API for memory allocation often used in process injection or",
    "contain obfuscated stackstrings top_rules Behavioral evidence of defense evasion through string obfuscation (T1027.005),",
    "domain, IP, url matches YARA rules detected network-related strings, which could indicate C2 or communication infrastruc"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Adload",
  "score": 80,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "CrossSectionJump, DynamicString, XorInLoop",
      "why": "Multiple obfuscation techniques (cross-section jumps, dynamic string construction, XOR loops) indicate potential defense evasion and code hiding, common in malicious software."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "kernel32.VirtualAllocEx",
      "why": "High-signal API for memory allocation often used in process injection or malicious code execution, a behavioral intent for defense evasion or execution."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain obfuscated stackstrings",
      "why": "Behavioral evidence of defense evasion through string obfuscation (T1027.005), a technique commonly employed by malware to evade static analysis."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "domain, IP, url",
      "why": "YARA rules detected network-related strings, which could indicate C2 or communication infrastructure, though content appears certificate-related and may require further analysis."
    }
  ],
  "summary": "The sample exhibits multiple obfuscation indicators (e.g., CrossSectionJump, DynamicString, XorInLoop) and high-signal imports like VirtualAllocEx, suggesting defense evasion and potential code injection. Capa confirms obfuscated stackstrings as a behavioral tactic. While local analysis does not reveal explicit C2, persistence, or data exfiltration, external VirusTotal detections with 58 malicious"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/prompt.txt` exists=`True` bytes=`28789` mtime=`2026-08-13T13:37:12.095255+00:00`
  - sha256: `96a6dde33924dc7ff33987f9faf12801d34171f1c23bc941f0013122bbb12d7f`
- **verdict:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/verdict.json` exists=`True` bytes=`6164` mtime=`2026-08-13T13:39:26.596341+00:00`
  - sha256: `5e8290f755102f458593ccb7cdde100bc900e3505b636f0c30cd156dcffea95b`

#### prompt_excerpt

```
# Triage evidence
sha256: 1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0
sample_path: /opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe
ghidra_session: ghidra-pe-1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0
ida_session: ida-1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Evidence: {malcat, imports_count, 125}, {ghidra, imports, 125}, {ida, imports, 125}; all tools report consistent import count of 125, within close agreement.
- functions: ghidra (confidence=medium) — Evidence: {ghidra, funcs, 34}, {ida, funcs, 27}, {malcat, functions_count, 10}; Ghidra and IDA show similar detailed counts (within 2x), while malcat's lower count suggests less comprehensive analysis, so Ghidra preferred.
- strings: both (confidence=high) — Evidence: {malcat, strings_count, 100}, {ghidra, strings, 185}, {ida, str
… [27738 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 80,
  "family_guess": "Adload",
  "cross_engine_notes": "Discrepancies in string and function counts across Ghidra, IDA, and Malcat indicate varied tool coverage; Malcat and Capa consistently detect obfuscation (e.g., CrossSectionJump, XorInLoop, obfuscated stackstrings). Ghidra and IDA show common DLL imports but no definitive C2 or payload strings. External VirusTotal detections (58 malicious) strongly suggest a known malware family, but local analysis lacks explicit behavioral evidence like C2 or persistence.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "CrossSectionJump, DynamicString, XorInLoop",
      "why": "Multiple obfuscation techniques (cross-section jumps, dynamic string construction, XOR loops) indicate potential defense evasion and code hiding, common in malicious software."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
    
… [5164 more chars]
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
  "rule_count": 13,
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
      "name": "accept command line arguments",
      "attack": [
        {
          "parts": [
            "Execution",
            "Command and Scripting Interpreter"
          ],
          "tactic": "Execution",
          "technique": "Command and Scripting Interpreter",
          "subtechnique": "",
          "id": "T1059"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Command and Scripting Interpreter"
          ],
          "objective": "Execution",
          "behavior": "Command and Scripting Interpreter",
          "method": "",
          "id": "E1059"
        }
      ]
    },
    {
      "name": "set file attributes",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "File and Directory Permissions Modification"
          ],
          "tactic": "Defense Evasion",
          "technique": "File and Directory Permissions Modification",
          "subtechnique": "",
          "id": "T1222"
        }
      ],
      "mbc": [
        {
          "parts": [
            "File System",
            "Set File Attributes"
          ],
          "objective": "File System",
          "behavior": "Set File Attributes",
          "method": "",
          "id": "C0050"
        }
      ]
    },
    {
      "name": "get disk size",
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
      "name": "create pipe",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Interprocess Communication",
            "Create Pipe"
          ],
          "objective": "Communication",
          "behavior": "Interprocess Communication",
          "method": "Create Pipe",
          "id": "C0003.001"
        }
      ]
    },
    {
   
… [2735 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 3388672,
  "duration_s": 0.03,
  "import_count": 125,
  "signal_count": 2,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
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
  "rule_count": 13,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3381736,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 320746,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 3349852,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 3384348,
          "length": 31,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 320183,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 3383296,
          "length": 133,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 3335760,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 3350124,
          "length": 11,
          "xor_key": nul
… [3252 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 484,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "Uqa9V]",
    "QxS<A\\",
    "!WK[TWKd",
    "ll%jO@",
    "A@Cr'q",
    "!gM^rJxH",
    "v6Kp/H",
    "dmKRuZ",
    "gm+|0*",
    "o}C%3V",
    "qxUzlQ",
    "nnWa{~",
    ".M0Q]]",
    "vyQ/}%",
    "2a-kp[",
    "B`f<K*",
    "H@uH3r",
    "R$`NNN4",
    "#K:1ntV",
    "Z{l+V7/",
    "UY+i4@",
    "2^iH,5",
    "Uo$4mL",
    "oFP_aA",
    "d5y!BR",
    "zah@*]?t",
    "N0n4e]",
    "buGr.5",
    "SuTp4 <",
    "47/v<#M",
    "yH|ADr",
    "0YWQrG",
    "U4]ske",
    "K]y_fz",
    "+&%Y,DE",
    "NYW^OTX",
    "HFlKB6",
    "Uz unDE",
    "$EhuFj",
    "[H-[ l\"",
    "]ac\"QE",
    "<od!M{",
    "Z?a=/i;",
    "8}12uJ",
    "C$r]T\"",
    "8?h\tC$:",
    "e0nA^e",
    "qGZ7~]f",
    "JV+%l(",
    "iH{S76",
    "2C}&\\V",
    "STZ(hf",
    "%\\4$RV",
    "Z''j{;",
    "=;;ZS$",
    "9qkQ?%",
    "BR`uLd",
    "97Lt:_lC",
    "2wwSOQ",
    "hqn,4r[)",
    "hBS97_g",
    "UVqs-@",
    "<;ejAe",
    ";U((>(",
    "DX&_2$y",
    "MF_V3%|",
    ">Madt#",
    "u8:aIGu\\YJ",
    "X4MS6}",
    "--?RFL",
    "<r{EL=KJ",
    "_]QUXA",
    "zy1?y\\y",
    "*MCQ-9I",
    "hJ%kCe",
    "3(_n#<",
    "v_bj1;"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 484
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 14.1,
  "size_bytes": 3388672,
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
  "sample": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
  "disassembly": {
    "0x0072f018": "\u250c 446: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_1ch @ ebp-0x1c\n\u2502           ; var int32_t var_20h @ ebp-0x20\n\u2502           ; var int32_t var_24h @ ebp-0x24\n\u2502           ; var int32_t var_2ch @ ebp-0x2c\n\u2502           ; var int32_t var_30h @ ebp-0x30\n\u2502           ; var int32_t var_34h @ ebp-0x34\n\u2502           ; var int32_t var_38h @ ebp-0x38\n\u2502           ; var int32_t var_3ch @ ebp-0x3c\n\u2502           ; var int32_t var_50h @ ebp-0x50\n\u2502           ; var int32_t var_54h @ ebp-0x54\n\u2502           ; var int32_t var_80h @ ebp-0x80\n\u2502           0x0072f018      6a70           push 0x70                   ; 'p' ; 112\n\u2502           0x0072f01a      6890267300     push 0x732690\n\u2502           0x0072f01f      e8f8010000     call 0x72f21c\n\u2502           0x0072f024      8d4580         lea eax, [var_80h]\n\u2502           0x0072f027      50             push eax\n\u2502           0x0072f028      ff1554217300   call dword [sym.imp.KERNEL32.dll_GetStartupInfoW] ; 0x732154 ; VOID GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)\n\u2502           0x0072f02e      66813d0000..   cmp word [0x400000], 0x5a4d ; 'MZ'\n\u2502                                                                      ; [0x400000:2]=0xffff\n\u2502       \u250c\u2500< 0x0072f037      7527           jne 0x72f060\n\u2502       \u2502   0x0072f039      a13c004000     mov eax, dword [0x40003c]   ; [0x40003c:4]=-1\n\u2502       \u2502   0x0072f03e      8d8000004000   lea eax, [eax + 0x400000]\n\u2502       \u2502   0x0072f044      813850450000   cmp dword [eax], 0x4550     ; 'PE'\n\u2502      \u250c\u2500\u2500< 0x0072f04a      7514           jne 0x72f060\n\u2502      \u2502\u2502   0x0072f04c      0fb74818       movzx ecx, word [eax + 0x18]\n\u2502      \u2502\u2502   0x0072f050      81f90b010000   cmp ecx, 0x10b              ; 267\n\u2502     \u250c\u2500\u2500\u2500< 0x0072f056      7421           je 0x72f079\n\u2502     \u2502\u2502\u2502   0x0072f058      81f90b020000   cmp ecx, 0x20b              ; 523\n\u2502    \u250c\u2500\u2500\u2500\u2500< 0x0072f05e      7406           je 0x72f066\n\u2502  \u250c\u250c\u2500\u2500\u2514\u2514\u2500> 0x0072f060      8365e400       and dword [var_1ch], 0\n\u2502  \u254e\u254e\u2502\u2502 \u250c\u2500< 0x0072f064      eb27           jmp 0x72f08d\n\u2502  \u254e\u254e\u2514\u2500\u2500\u2500\u2500> 0x0072f066      83b8840000..   cmp dword [eax + 0x84], 0xe\n\u2502  \u2514\u2500\u2500\u2500\u2500\u2500\u2500< 0x0072f06d      76f1           jbe 0x72f060\n\u2502   \u254e \u2502 \u2502   0x0072f06f      33c9           xor ecx, ecx\n\u2502   \u254e \u2502 \u2502   0x0072f071      3988f8000000   cmp dword [eax + 0xf8], ecx\n\u2502   \u254e \u2502\u250c\u2500\u2500< 0x0072f077      eb0e           jmp 0x72f087\n\u2502   \u254e \u2514\u2500\u2500\u2500> 0x0072f079      8378740e       cmp dword [eax + 0x74], 0xe\n\u2502   \u2514\u2500\u2500\u2500\u2500\u2500< 0x0072f07d      76e1           jbe 0x72f060\n\u2502      \u2502\u2502   0x0072f07f      33c9           xor ecx, ecx\n\u2502      \u2502\u2502   0x0072f081      3988e8000000   cmp dword [eax + 0xe8], ecx\n\u2502      \u2502\u2502   ; CODE XREF from entry0 @ 0x72f077(x)\n\u2502      \u2514\u2500\u2500> 0x0072f087      0f95c1 
… [510 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
  "sample": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
    "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
    "exists": true,
    "hook_candidates": [
      "msvcrt.dll!_controlfp",
      "msvcrt.dll!_except_handler3",
      "msvcrt.dll!__set_app_type",
      "msvcrt.dll!__p__fmode",
      "msvcrt.dll!__p__commode",
      "KERNEL32.dll!VirtualFree",
      "KERNEL32.dll!SetConsoleOutputCP",
      "KERNEL32.dll!GlobalUnlock",
      "KERNEL32.dll!WritePrivateProfileSectionW",
      "KERNEL32.dll!VirtualAlloc",
      "ADVAPI32.dll!RegOpenKeyW",
      "USER32.dll!DrawIcon",
      "USER32.dll!AppendMenuW",
      "USER32.dll!CharNextW",
      "GDI32.dll!GetWorldTransform",
      "GDI32.dll!CreateMetaFileW",
      "GDI32.dll!GetCharWidthW",
      "GDI32.dll!GetKerningPairsW",
      "GDI32.dll!CreateCompatibleBitmap"
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
    "Malcat anomalies: 10 detected including invalid checksum, high-entropy entry (7.9 bits), code in overlay at 0x33a400, hi",
    "Certificate abuse: stolen cert from 'Kharkiv Vagon-Remont, LLC' (Ukraine, COMODO CA, expired 2017-12-05); ProgramName co",
    "CAPA: obfuscated stackstrings (T1027.005), create process (T1059), read/write files, create mutex, get disk size (T1082)",
    "FLOSS: 484 static strings found, 0 decoded strings; all referenced strings are random-encoded sequences confirming heavy",
    "Import signals: VirtualAllocEx (process injection T1055), LoadLibrary (T1129); also OpenThread, CreateMutexW, CreateFile"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This is a packed dropper/loader (rootkit dropper) with heavy string obfuscation, process injection capabilities, and C2 infrastructure embedded in the PE overlay. The sample uses a stolen/expired Ukrainian code signing certificate from 'Kharkiv Vagon-Remont, LLC' (COMODO CA, valid 2017-01-27 to 2017",
  "key_evidence": [
    "Malcat anomalies: 10 detected including invalid checksum, high-entropy entry (7.9 bits), code in overlay at 0x33a400, high-entropy overlay (7.8 bits), orphan debug directory, suspicious certificate origin",
    "Certificate abuse: stolen cert from 'Kharkiv Vagon-Remont, LLC' (Ukraine, COMODO CA, expired 2017-12-05); ProgramName contains encoded payload data: '9TqdEZ3BMHS0Gr1RQ4cXO8qnshebwP3RGTUZu0gheTajKJUHuJ7HsZonW0GlopENypY8gj3nkb7xoPK2SBeR3bcvE2AV5tA2YnqfqzsLO2WZwt165Du4UTUBmrqZuFu23N5XmhufmR1LapahkVAXyrwrEPiJwLS6YJMTwFaHAdyXajU4Iri8kX7ZeJG0etkDW'",
    "CAPA: obfuscated stackstrings (T1027.005), create process (T1059), read/write files, create mutex, get disk size (T1082), get common file paths (T1083), set file attributes (T1222), reference anti-analysis tools strings (13 rules matched)",
    "FLOSS: 484 static strings found, 0 decoded strings; all referenced strings are random-encoded sequences confirming heavy runtime string obfuscation",
    "Import signals: VirtualAllocEx (process injection T1055), LoadLibrary (T1129); also OpenThread, CreateMutexW, CreateFileW, WriteFile, CreateNamedPipeW, CreatePipe, GetLogicalDriveStringsW, RegOpenKeyW",
    "Ghidra function metrics: FUN_00731260 has cyclomatic complexity 81, 638 instructions, 122 blocks, 18 call-outs, 8 string refs \u2014 indicates complex obfuscated/CFF main payload function",
    "All Ghidra string_refs to encoded strings: 'keuwosaippaldeaa', 'ottrcvfayshjoutoyipnezimhtv', 'nulmwfohcwntecottryari', 'cpagdsrpuigpkogsroyo', 'dsathahhrddowfsntrr' etc. \u2014 XOR-encoded stack strings",
    "YARA matches: IP address at offset 0x33a000 (in overlay), URL at 0x33b61c (in overlay), base64 at 0x331c9c, mutex at 0x331e2c, file operations patterns, maldoc getEIP technique",
    "Manifest requests requireAdministrator privileges; original filename getoohun.exe / GETOOHUN.EXE; product GETOOHUN v1.3.9.6; company '\u00a9Iofu' (suspicious)",
    "Large single .text section (3.3MB, entropy 7.9) indicates packed/encrypted payload with overlay containing additional C2 infrastructure"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 13,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
      "path": "/opt/sample
… [6352 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
    "file_name": "rk-dropper.exe",
    "file_pa
… [79536 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 13,
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
… [5835 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 3388672,
  "duration_s": 0.03,
  "import_count": 125,
  "signal_count": 2,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
      "attack": [
        "T1129"
      ]
    }
  ],
  "hint": "PE i
… [44 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 484,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "Uqa9V]",
    "QxS<A\\",
    "!WK[TWKd",
    "ll%jO@",
    "A@Cr'q",
    "!gM^rJxH",
    "v6Kp/H",
    "dmKRuZ",
    "gm+|0*",
    "o}C%3V",
    "qxUzlQ",
    "nnWa{~",
    ".M0Q]]",
    "vyQ/}%",
    "2a-kp[",
    "B`f<K*",
    "H@uH
… [1272 more chars]
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
  "sample": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
  "disassembly": {
    "0x0072f018": "\u250c 446: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_1ch @ ebp-0x1c\n\u2502           ; var int32_t var_20h @ ebp-0x20\n\u2502           ; var int32_t var_24h @ ebp-0x2
… [3610 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch
… [17 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
    "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
    "exists": true,
    "hook_candidates": [
      "msvcrt.dll!_controlfp",
      "msvcrt.dll!_except_handler3",
      "msvcrt.dll!__set_app_type",
      "msvcrt.dll!__p__fmode",
      "msvcrt.dll!__p__com
… [520 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 3346432,
      "entropy": 4.6296,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 5120,
      "entropy": 5.0467,
      "executable":
… [384 more chars]
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
… [1768 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 3,
  "sinks": [
    {
      "api": "virtualalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x72fa4a",
      "function": "fcn.0072f9d0"
    },
    {
      "api": "virtualalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x730cf5",
      "function
… [262 more chars]
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
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 0.47,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.26,
 
… [101 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "none",
  "name": null,
  "score": 1
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
      "name": "FUN_00731260",
      "address": "7541344",
      "size": "2205"
    },
    {
      "name": "FUN_0072f270",
      "address": "7533168",
      "size": "677"
    },
    {
      "name": "FUN_007308e0",
      "address": "7538912",
      "size": "586"
    },
    {
      "name": "FUN_0072fab0",
      "address": "
… [2247 more chars]
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
      "content": "_wcmdln",
      "address": "7547216",
      "length": "8"
    },
    {
      "content": "msvcrt.dll",
      "address": "7547358",
      "length": "11"
    },
    {
      "content": "CreateMutexW",
      "address": "7547500",
      "length": "13"
    },
    {
      "content": "GetLogicalDriveStrings
… [1406 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 3388672,
  "duration_s": 0.06,
  "import_count": 125,
  "signal_count": 2,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
      "attack": [
        "T1129"
      ]
    }
  ],
  "hint": "PE i
… [44 more chars]
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
      "name": "RegOpenKeyW",
      "module": "ADVAPI32.DLL",
      "address": "79"
    },
    {
      "name": "CreateCompatibleBitmap",
      "module": "GDI32.DLL",
      "address": "87"
    },
    {
      "name": "CreateDIBPatternBrushPt",
      "module": "GDI32.DLL",
      "address": "110"
    },
    {
      "name": 
… [2447 more chars]
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
  "session_id": "ghidra-pe-1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0",
  "audit_path": "/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/audit.jsonl"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: name`

```json
{
  "error": "ghidrasql SQL error: no such column: name"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "str",
    "func_name",
    "func_addr"
  ],
  "rows": [
    {
      "str": "keuwosaippaldeaa",
      "func_name": "FUN_007308e0",
      "func_addr": "7538912"
    },
    {
      "str": "ottrcvfayshjoutoyipnezimhtv",
      "func_name": "FUN_00731260",
      "func_addr": "7541344"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_que
… [213 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0.json"
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
      "content": "msvcrt.dll",
      "address": "7547358",
      "length": "11"
    },
    {
      "content": "KERNEL32.dll",
      "address": "7548592",
      "length": "13"
    },
    {
      "content": "ADVAPI32.dll",
      "address": "7548620",
      "length": "13"
    },
    {
      "content": "USER32.dll",
   
… [2110 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "instruction_count",
    "block_count",
    "cyclomatic_complexity",
    "call_in_count",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": "FUN_00731260",
      "func_addr": "7541344",
      "size": "2205",
      "instruction_count": "638",
      "block_count": "122",
      "cyclomatic_complexi
… [4372 more chars]
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
      "content": "ottrcvfayshjoutoyipnezimhtv",
      "address": "7546264",
      "length": "56"
    },
    {
      "content": "nulmwfohcwntecottryari",
      "address": "7545644",
      "length": "48"
    },
    {
      "content": "chaimnaftinfsnothcko",
      "address": "7546328",
      "length": "44"
    },
    {
… [5017 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 13,
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
… [5835 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 484,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "Uqa9V]",
    "QxS<A\\",
    "!WK[TWKd",
    "ll%jO@",
    "A@Cr'q",
    "!gM^rJxH",
    "v6Kp/H",
    "dmKRuZ",
    "gm+|0*",
    "o}C%3V",
    "qxUzlQ",
    "nnWa{~",
    ".M0Q]]",
    "vyQ/}%",
    "2a-kp[",
    "B`f<K*",
    "H@uH
… [1273 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name",
    "func_addr",
    "ref_addr"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0",
  "audit_path": "/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/audit.jsonl"
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
      "content": "cpsituarttcw",
      "func_name": "FUN_0072f640",
      "func_addr": "7534144"
    },
    {
      "content": "ssee",
      "func_name": "FUN_0072fab0",
      "func_addr": "7535280"
    },
    {
      "content": "rhie",
      "func_name": "FUN_00730060",
      "func_addr": "7536736"
    },
    
… [2173 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
    "file_name": "rk-dropper.exe",
    "file_pa
… [78802 more chars]
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
  "session_id": "ghidra-pe-1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0",
  "audit_path": "/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/audit.jsonl"
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0",
  "audit_path": "/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/audit.jsonl"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/deep_dive/01-tools-raw.json` exists=`True` bytes=`117088` mtime=`2026-08-13T13:36:38.463115+00:00`
  - sha256: `3cbdd6b5d2fb09c4f06f0a22b6991b749f811bba8c4d48e7f1ea508e263edfd6`
- **sql_evidence:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/deep_dive/05-deep-dive.json` exists=`True` bytes=`5083` mtime=`2026-08-12T22:36:49.308439+00:00`
  - sha256: `a6d4b1488c902528ef15c7ec923ddaecda01c57fc6f21abb1e9f0734ab0c442b`

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
  "summary": "This is a packed dropper/loader (rootkit dropper) with heavy string obfuscation, process injection capabilities, and C2 infrastructure embedded in the PE overlay. The sample uses a stolen/expired Ukrainian code signing certificate from 'Kharkiv Vagon-Remont, LLC' (COMODO CA, valid 2017-01-27 to 2017-12-05) with encoded payload data embedded in the certificate ProgramName field. The binary contains high-entropy packed code (7.9 bits in .text, 7.8 in overlay), obfuscated stack strings (CAPA T1027.005, FLOSS decoded 0 of 484 strings), process injection APIs (VirtualAllocEx, OpenThread), mutex-based single-instance control, file I/O, process creation, registry access, and net
… [4283 more chars]
```

- **agentic:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`562170` mtime=`2026-08-12T22:36:49.308439+00:00`
  - sha256: `d32982b2d63105719e02995ec129b8a9b0b02fc5c0a2d0ab3eea7f93cab16c31`

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

- **rule_yar:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rule.yar` exists=`True` bytes=`1161` mtime=`2026-08-12T22:36:52.322431+00:00`
  - sha256: `e544b668faa64eb6378d5b375ae84ce143b2823d8479e33fa9421fb222992d4f`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T22:36:52.323329+00:00
import "pe"
rule CADRE_v2_adload_fugrafa_1196afa54d18 {
    meta:
        description = "RevAI v2 auto rule for adload/fugrafa"
        sha256 = "1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0"
        family = "adload_fugrafa"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "!WK[TWKd" ascii wide
        $s2 = "!gM^rJxH" ascii wide
        $s3 = "zah@*]?t" ascii wide
        $s4 = "97Lt:_lC" ascii wide
        $s5 = "hqn,4r[)" ascii wide
        $s6 = "u8:aIGu\\YJ" ascii wide
        $s7 = "<r{EL=KJ" ascii wide
        $s8 = "GetNu
… [359 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/REPORT-MASTER-v2.md` exists=`True` bytes=`17297` mtime=`2026-08-13T13:45:50.615959+00:00`
  - sha256: `7b360d70cc543deed97b2be1dbc78f35c513dfa2ea73bca0e42b7bae65a6578f`
- **REPORT_MASTER_v3:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/REPORT-MASTER-v3.md` exists=`True` bytes=`49224` mtime=`2026-08-13T13:57:20.332275+00:00`
  - sha256: `dac70b55ef58f5326ccd85db23ab9de9b7e4a0188bf3486d60eb8fa41d7652fb`
- **REPORT_v2:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/REPORT-v2.md` exists=`True` bytes=`17297` mtime=`2026-08-13T13:45:50.615959+00:00`
  - sha256: `7b360d70cc543deed97b2be1dbc78f35c513dfa2ea73bca0e42b7bae65a6578f`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`56147` mtime=`2026-08-13T13:48:45.700553+00:00`
  - sha256: `31e959f10b3d7af11b0d87314ae02d5d8c6b396b39b14a69cc507306fe266b7a`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`53827` mtime=`2026-08-13T14:04:15.607013+00:00`
  - sha256: `b6de993942b74244342a4a02d64fb5da7bc1ff0dcde33975c8c2e0d55e02e0f1`
- **report_v2_json:** `/opt/samples/logs/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/report-v2.json` exists=`True` bytes=`20410` mtime=`2026-08-13T13:48:45.703553+00:00`
  - sha256: `689f3cf5148ee6814500cec84c0cb03f013807634710e741d3ff123ffc2166d7`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:45:50 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Adload
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary

This report details th
… [16382 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:57:20 UTC

# RE Report — 1196afa54d18
_Generated 2026-08-13T13:57:20.324142+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=233c | cross_refs=True | llm_ok=True | runtime=61.13s -->

# Executive Summary

The sample with SHA256 `1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0` is assessed as **malicious** with **high confidence**, belonging to the **Adload** malware family. Confidence is derived from a deep dive agentic analysis that assigned a 90% certainty score (source: deep_dive_agentic, row: deep_confidence, why: detailed examination of code and behavior patterns, such
… [48313 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
