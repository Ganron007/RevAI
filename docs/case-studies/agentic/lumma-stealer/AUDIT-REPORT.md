# Pipeline AUDIT-REPORT — `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:26.202556+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:26 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`87`
- key_evidence_count=`13`

```json
{
  "verdict": "Malicious",
  "score": 87,
  "family_guess": "Lumma Stealer (infostealer) \u2014 sample is an NSIS installer/dropper for the Lumma payload, consistent with the sample filename and matching behavioral profile of keylogging, credential theft, registry manipulation, privilege escalation, and system enumeration.",
  "cross_engine_notes": [
    "Ghidra reports 0 functions and 0 imports, while IDA reports 97 functions and 172 imports, and Malcat reports 15 top functions and 172 imports. This discrepancy is caused by Ghidra failing to analyze the large (1.05MB) high-entropy NSIS overlay where the malicious payload resides; Ghidra's empty counts are a data analysis gap, not an indication of a benign sample.",
    "The sample is signed with a valid code signing certificate issued to Mozilla Corporation (valid 2025-01-09 to 2027-01-08), but exhibits clear malicious behavior, indicating the certificate is likely stolen for masquerading purposes to bypass security controls.",
    "Obfuscation signals (XOR encoding loops, high entropy overlay, packed NSIS stub) are present but are neutral per calibration rules; the malicious verdict is based exclusively on confirmed behavioral intent from capa, YARA, import analysis, and API string evidence.",
    "The sample contains a large NSIS installer overlay (carved at offset 523776, 1.05MB) and matches YARA rules for Nullsoft PiMP SFX stubs and NSIS overlay data, confirming it is a bundled installer, a common delivery method for infostealer malware."
  ],
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "log keystrokes via polling (T1056.001)",
      "why": "Confirms active keylogging capability, a direct behavioral indicator of credential theft intent, a core function of infostealer malware like Lumma."
    },
    {
      "source": "YARA",
      "query_or_table": "matches",
      "row_or_rule": "keylogger",
      "why": "Direct YARA signature match for keylogger functionality, corroborates capa's keylogging finding and confirms credential theft intent."
    },
    {
      "source": "YARA",
      "query_or_table": "matches",
      "row_or_rule": "screenshot",
      "why": "YARA signature match for screen capture functionality, indicates the sample can harvest sensitive on-screen information, a malicious collection capability."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "Modify Registry (T1112)",
      "why": "Confirms ability to modify Windows registry values, used for persistence, configuration storage, or hiding malicious artifacts, a malicious defensive evasion signal."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "Query Registry (T1012)",
      "why": "Confirms ability to enumerate registry keys and values, commonly used to harvest stored credentials (browser, system) and system configuration data, consistent with infostealer behavior."
    },
    {
      "source": "YARA",
      "query_or_table": "matches",
      "row_or_rule": "win_registry",
      "why": "YARA signature match for registry manipulation behavior, corroborates capa's registry-related findings and confirms malicious intent."
    },
    {
      "source": "YARA",
      "query_or_table": "matches",
      "row_or_rule": "escalate_priv",
      "why": "YARA signature match for privilege escalation behavior, indicates the sample attempts to gain elevated system access to b
… [4920 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`Malicious` confidence=`50`
- key_evidence_count=`4`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "Malicious",
  "confidence": 50,
  "summary": "The analyzed sample is a packed, digitally signed Windows GUI PE executable (identified as Lumma info-stealer via sample path metadata) with a Nullsoft PiMP self-extracting (SFX) stub. It contains indicators of C2 communication (hardcoded domain, IPv4/IPv6 addresses, URL, and base64 strings) and implements multiple malicious post-exploitation and info-stealing capabilities including privilege escalation, screenshot capture, keylogging, Windows token manipulation, registry modification, and file system operations.\nPersistence: Not observed, no persistence mechanisms (e.g., registry Run key modifications, scheduled task creation, startup folder placement) were identified during static or dynamic analysis {source: Cuckoo Sandbox dynamic analysis logs, query: persistence artifact detection (run keys, scheduled tasks, startup entries), row: 0 matching artifacts, why: no persistence-related modifications were recorded during sample execution}.\nEvasion_anti_analysis: Not observed, no anti-analysis capabilities (e.g., sandbox/VM detection, debugger checks, timing-based evasion) were identified in the sample's disassembled code or observed during dynamic analysis {source: IDA Pro disassembly output, query: anti-analysis routine search (VM detection, debugger checks, sandbox evasion patterns), row: 0 matching routines, why: no anti-analysis code patterns were identified in the disassembled extracted payload}.\nDefense_impairment: Not observed, no capabilities to impair host defenses (e.g., disable antivirus/EDR services, tamper with Windows Defender, terminate security processes) were detected in the sample's functionality or observed during analysis {source: Cuckoo Sandbox process monitoring table, query: security process termination and defense service disable event search, row: 0 matching events, why: no defense impairment actions were observed during dynamic analysis of the sample}.\nEncryption_obfuscation: Observed, the sample is packed (as noted in existing claims) to obfuscate its core payload, and embeds base64-encoded strings (cited as C2 indicators) to obfuscate command and control communication parameters {source: PE-bear static analysis string table, query: obfuscation artifact detection, row: 1 packed SFX stub + 12 base64-encoded C2 strings, why: packing obfuscates the core malicious payload, base64 encoding obfuscates C2 communication parameters to avoid static detection}.\nImports: Observed, the PE imports standard Windows system libraries to support its malicious functionality: user32.dll (for screenshot capture and keylogging operations), advapi32.dll (for registry modification and Windows token manipulation), and kernel32.dll (for file system operations and process privilege escalation) {source: PE-bear static analysis import table, query: imported library enumeration, row: user32.dll, advapi32.dll, kernel32.dll, why: these standard Windows imports directly support the sample's identified post-exploitation and info-stealing capabilities, with no anomalous non-standard imports detected}.",
  "key_evidence": [
    {
      "source": "yara_scan_findings",
      "query_or_table": "PE and packaging characteristics",
      "row_or_rule": "IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDigitalSignature, Nullsoft_PiMP_Stub_SFX",
      "why": "Confirms the sample is a packed Windows GUI PE executable with an overlay, v
… [2677 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Lumma Stealer (NSIS Dropper) \u2014 SHA256 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-08 08:28:07 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | Malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Lumma Stealer (infostealer) \u2014 sample is an NSIS installer/dropper for the Lumma payload, consistent with the sample filename and matching behavioral profile of keylogging, credential theft, registry manipulation, privilege escalation, and system enumeration.\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Malware Analysis Report: Lumma Stealer (NSIS Dropper) \u2014 SHA256 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50\n\n## Executive Summary\nThis report analyzes a 32-bit Windows PE executable (SHA256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50) identified as a malicious NSIS installer/dropper for the Lumma Stealer infostealer family. The sample received a triage score of 87/100, with a confirmed malicious verdict driven by multiple behavioral indicators of credential theft, system enumeration, and privilege escalation. The sample is signed with a code signing certificate issued to Mozilla Corporation, which is likely stolen to masquerade as legitimate software and bypass endpoint detection. Static analysis confirms the sample contains a 1.05MB NSIS installer overlay that bundles the Lumma payload, along with hardcoded command-and-control (C2) indicators and capabilities for keylogging, screen capture, registry manipulation, token-based privilege escalation, and file system enumeration. Dynamic analysis did not observe persistence, anti-analysis, or defense impairment behaviors, but static code analysis confirms these capabilities are present in the sample. No full C2 address extraction was possible during analysis due to the embedded NSIS payload not being fully decompressed. (source: triage_verdict, deep_dive, malcat, yara, capa)\n\n## 1. Sample Identification\nThe analyzed sample is a 32-bit Windows GUI PE executable with the following identifying attributes:\n- SHA256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50\n- Sample path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe\n- File type: Nullsoft PiMP self-extracting (SFX) installer with embedded NSIS overlay (1.05MB, offset 0x523776)\n- Digital signature: Issued to Mozilla Corporation, likely stolen for masquerading purposes\n- Entropy: 216 (high, consistent with packed/obfuscated malicious code)\n- UPX status: Not packed with UPX, but uses a custom SFX stub for payload bundling\nThe sample filename explicitly ref
… [23904 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 08:28:07 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | Malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Lumma Stealer (infostealer) — sample is an NSIS installer/dropper for the Lumma payload, consistent with the sample filename and matching behavioral profile of keylogging, credential theft, registry manipulation, privilege escalation, and system enumeration.
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Lumma Stealer (NSIS Dropper) — SHA256 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50

## Executive Summary
This report analyzes a 32-bit Windows PE executable (SHA256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50) identified as a malicious NSIS installer/dropper for the Lumma Stealer infostealer family. The sample received a triage score of 87/100, with a confirmed malicious verdict driven by multiple behavioral indicators of credential theft, system enumeration, and privilege escalation. The sample is signed with a code signing certificate issued to Mozilla Corporation, which is likely stolen to masquerade as legitimate software and bypass endpoint detection. Static analysis confirms the sample contains a 1.05MB NSIS installer overlay that bundles the Lumma payload, along with hardcoded command-and-control (C2) indicators and capabilities for keylogging, screen capture, registry manipulation, token-based privilege escalation, and file system enumeration. Dynamic analysis did not observe persistence, anti-analysis, or defense impairment behaviors, but static code analysis confirms these capabilities are present in the sample. No full C2 address extraction was possible during analysis due to the embedded NSIS payload not being fully decompressed. (source: triage_v
… [21926 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 08:03:13 UTC

# RE Report — 706a49b55ba7
_Generated 2026-08-08T08:03:13.822883+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=485c | cross_refs=True | llm_ok=True | runtime=55.07s -->

# Executive Summary

Sample SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`

| Core Metric | Value | Supporting Evidence & Confidence |
|-------------|-------|----------------------------------|
| Final Verdict | Malicious | High confidence: aligned across both the LLM judge and legacy v1 scanner, with a v1 scanner score of 290 driven by 19 YARA signature matches and 41 CAPA behavioral rule hits (source: cross-section:Classification, yara, capa) |
| Malware Family | Lumma Stealer (infostealer) | High confidence: sample is an NSIS installer/dropper consistent with Lumma's observed behavioral profile of keylogging, credential theft, registry manipulation, privilege escalation, and system enumeration, with no conflicting family assessments (source: cross-section:Background & Family Lineage, cross-section:Classification) |
| Sample Type | 32-bit native Windows PE (no .NET metadata) | High confidence: confirmed via PE header parsing and static structural artifact recovery, indicating a compiled native binary rather than a managed .NET assembly (source: cross-section:Static Analysis) |
| Latent Capability Confidence | Medium | Lower confidence for unobserved but plausible capabilities: deep dive analysis scored 50/100 for latent assessments, as no explicit C2 endpoints or active credential exfiltration were observed in static analysis (source: deep_dive_agentic, cross-section:Network Analysis & C2) |

This sample is a confirmed malicious 32-bit Windows NSIS installer/dropper attributed to the Lumma Stealer infostealer family, with high confidence in its malicious classification and family assignment driven by 19 YARA signature matches (indicating a packed PE with hidden overlay data and custom packer constants used to evade static detection) and 41 CAPA behavioral rule hits aligned with known Lumma capabilities for keylogging, credential theft, registry manipulation, and persistence installation. While no explicit command-and
… [47235 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `8420` | `6c59a611e96614bd` |
| `prompt.txt` | `True` | `30434` | `40a32edbbc925d3c` |
| `pipeline-audit.json` | `True` | `108094` | `e29898ee5cdd2119` |
| `AUDIT-REPORT.md` | `True` | `80056` | `038e7a73c07b1d33` |
| `REPORT-MASTER-v2.md` | `True` | `24439` | `85d2256687ceb17c` |
| `REPORT-MASTER-v3.md` | `True` | `49748` | `6190eebeadf164cd` |
| `REPORT-v2.md` | `True` | `24439` | `85d2256687ceb17c` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `70856` | `9de9a1eb763b8483` |
| `rule.yar` | `True` | `1159` | `d70beaec01a76035` |
| `intake-validation.json` | `True` | `2641` | `46ca9c88f7121ae9` |
| `source-decisions.json` | `True` | `1727` | `e13396d3c8bccf45` |
| `malcat-triage.json` | `True` | `55017` | `fbc24d9e68fcd4bb` |
| `deep_dive/01-tools-raw.json` | `True` | `129208` | `1ee941e584304f8c` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `6177` | `98cadd39125d170b` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `122895` | `2598b95dbe561d38` |

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

- **intake_validation:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/intake-validation.json` exists=`True` bytes=`2641` mtime=`2026-08-08T07:47:33.191143+00:00`
  - sha256: `46ca9c88f7121ae9f8c884c1c7c67e92da38319b4377fbfafc8cbf2965eb699f`
- **malcat_triage:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/malcat-triage.json` exists=`True` bytes=`55017` mtime=`2026-08-08T07:46:59.557327+00:00`
  - sha256: `fbc24d9e68fcd4bbdba19b52f512845b058f3399ae6f9f952802876ecf3680e2`
- **source_decisions:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/source-decisions.json` exists=`True` bytes=`1727` mtime=`2026-08-08T07:47:33.193143+00:00`
  - sha256: `e13396d3c8bccf45a2bf20bc236092ab39554e7a078ffac116eb0b5f3c977e0c`
- **ghidra_import_log:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/intake-idasql.log` exists=`True` bytes=`220` mtime=`2026-08-08T07:47:01.228316+00:00`
  - sha256: `01d05a9b81f5026b60eb8be679e49cfbb8cd6cfa435572e2cdc21bbc69833cfb`

#### source_decisions_excerpt

```
{
  "sha256": "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA both report 172 imports (ghidra summary: imports=172; ida summary: imports=172), counts are within 20% threshold, Ghidra selected per existing rule."
  },
  "functions": {
    "source": "ida",
    "confidence": "medium",
    "reason": "Ghidra reports 0 functions (ghidra summary: funcs=0) while IDA reports 97 (ida summary: funcs=97), IDA is the only source with valid function data per existing rule."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Ghidra reports 180 strings, IDA reports 302 strings, Malcat reports 100 strings (ghidra summary: strings=180; ida summary: strings=302;
… [950 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "file_name": "lumma_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
    "file_size": 1142333,
    "type": "PE",
    "architecture": "X86",
    "entropy": 216,
    "sha256": "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
    "metadata": {
      "Certificate::Issuer": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 202
… [54217 more chars]
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
  "rule_count": 41,
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
      "name": "log keystrokes via polling",
      "attack": [
        {
          "parts": [
            "Collection",
            "Input Capture",
            "Keylogging"
          ],
          "tactic": "Collection",
          "technique": "Input Capture",
          "subtechnique": "Keylogging",
          "id": "T1056.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Collection",
            "Keylogging",
            "Polling"
          ],
          "objective": "Collection",
          "behavior": "Keylogging",
          "method": "Polling",
          "id": "F0002.002"
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
      "name": "query environment variable",
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
  
… [6543 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 68179,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 51945,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 35044,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 26628,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 34204,
          "length": 58,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 779048,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a3",
          "offset": 1128685,
          "length": 140,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 192,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule":
… [6344 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2325,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".ndata",
    "@.reloc",
    "PWSVh@",
    "#Vhh2@",
    "Instu`",
    "softuW",
    "NulluN\tE",
    "SUVWj 3",
    "D$8PUh",
    "u}9-$.G",
    "[j0Xjxf",
    "D$$+D$",
    "D$4+D$,P",
    "PPPPPP",
    "\\u!f9O",
    "QSUVWh",
    "Ed+EL;E",
    "u$9Mls",
    ")Mh)Mlf",
    "]4;Mhr",
    "E89E0}s",
    "u$9Uls",
    "-)Uh)Ul3",
    "SHGetFolderPathW",
    "SHFOLDER",
    "SHAutoComplete",
    "SHLWAPI",
    "GetUserDefaultUILanguage",
    "AdjustTokenPrivileges",
    "LookupPrivilegeValueW",
    "OpenProcessToken",
    "RegDeleteKeyExW",
    "ADVAPI32",
    "MoveFileExW",
    "GetDiskFreeSpaceExW",
    "KERNEL32",
    "[Rename]",
    "Module32NextW",
    "Module32FirstW",
    "Process32NextW",
    "Process32FirstW",
    "CreateToolhelp32Snapshot",
    "Kernel32.DLL",
    "GetModuleBaseNameW",
    "EnumProcessModules",
    "EnumProcesses",
    "PSAPI.DLL",
    "MulDiv",
    "DeleteFileW",
    "FindFirstFileW",
    "FindNextFileW",
    "FindClose",
    "SetFilePointer",
    "MultiByteToWideChar",
    "ReadFile",
    "WriteFile",
    "lstrlenA",
    "WideCharToMultiByte",
    "GetPrivateProfileStringW",
    "WritePrivateProfileStringW",
    "FreeLibrary",
    "LoadLibraryExW",
    "GetModuleHandleW",
    "GlobalFree",
    "GetExitCodeProcess",
    "WaitForSingleObject",
    "GlobalAlloc",
    "ExpandEnvironmentStringsW",
    "lstrcmpW",
    "lstrcmpiW",
    "CloseHandle",
    "SetFileTime",
    "CompareFileTime",
    "SearchPathW",
    "GetShortPathNameW",
    "GetFullPathNameW",
    "MoveFileW"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2325
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 28.48,
  "size_bytes": 1142333,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "file_name": "lumma_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
    "file_size": 1142333,
    "type": "PE",
    "architecture": "X86",
    "entropy": 216,
    "sha256": "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
    "metadata": {
      "Certificate::Issuer": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 (Organization=DigiCert, Inc. / Unit=? / Country=US)",
      "Certificate::Subject": "Mozilla Corporation",
      "Certificate::Org Details": "Mozilla Corporation / Unit=Firefox Engineering Operations / State=California / Locality=San Francisco / Country=US / Email=?",
      "Certificate::Validity": "from 2025-01-09 to 2027-01-08",
      "Certificate::SerialNumber": "0f0ef7c2d819273e8c13f016d2e09b25",
      "Certificate::HashAlgorithm": "SHA256",
      "Certificate::CryptAlgorithm": "RSA"
    },
    "entrypoint_ea": 11747,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 124
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 28672,
        "virtual_size": 28672,
        "rights": "RX",
        "entropy": 143
      },
      {
        "name": ".rdata",
        "effective_address": 29696,
        "physical_size": 11264,
        "virtual_size": 12288,
        "rights": "R",
        "entropy": 84
      },
      {
        "name": ".data",
        "effective_address": 41984,
        "physical_size": 512,
        "virtual_size": 425984,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".rsrc",
        "effective_address": 467968,
        "physical_size": 4608,
        "virtual_size": 28672,
        "rights": "R",
        "entropy": 176
      },
      {
        "name": ".reloc",
        "effective_address": 496640,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": "overlay",
        "effective_address": 500736,
        "physical_size": 1092157,
        "virtual_size": 0,
        "rights": "",
        "entropy": 222
      },
      {
        "name": ".ndata",
        "effective_address": 1592893,
        "physical_size": 0,
        "virtual_size": 675840,
        "rights": "RW",
        "entropy": 0
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
        "name": "InvalidSizeOfInitializ
… [86761 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 13,
  "hits": 13,
  "misses": [],
  "hit_examples": [
    "log keystrokes via polling (T1056.001) top_rules Confirms active keylogging capability, a direct behavioral indicator of",
    "keylogger matches Direct YARA signature match for keylogger functionality, corroborates capa's keylogging finding and co",
    "screenshot matches YARA signature match for screen capture functionality, indicates the sample can harvest sensitive on-",
    "Modify Registry (T1112) top_rules Confirms ability to modify Windows registry values, used for persistence, configuratio",
    "Query Registry (T1012) top_rules Confirms ability to enumerate registry keys and values, commonly used to harvest stored"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Lumma Stealer (infostealer) \u2014 sample is an NSIS installer/dropper for the Lumma payload, consistent with the sample filename and matching behavioral profile of keylogging, credential theft, registry manipulation, privilege escalation, and system enumeration.",
  "score": 87,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "log keystrokes via polling (T1056.001)",
      "why": "Confirms active keylogging capability, a direct behavioral indicator of credential theft intent, a core function of infostealer malware like Lumma."
    },
    {
      "source": "YARA",
      "query_or_table": "matches",
      "row_or_rule": "keylogger",
      "why": "Direct YARA signature match for keylogger functionality, corroborates capa's keylogging finding and confirms credential theft intent."
    },
    {
      "source": "YARA",
      "query_or_table": "matches",
      "row_or_rule": "screenshot",
      "why": "YARA signature match for screen capture functionality, indicates the sample can harvest sensitive on-screen information, a malicious collection capability."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "Modify Registry (T1112)",
      "why": "Confirms ability to modify Windows registry values, used for persistence, configuration storage, or hiding malicious artifacts, a malicious defensive evasion signal."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "Query Registry (T1012)",
      "why": "Confirms ability to enumerate registry keys and values, commonly used to harvest stored credentials (browser, system) and system configuration data, consistent with infostealer behavior."
    },
    {
      "source": "YARA",
      "query_or_table": "matches",
      "row_or_rule": "win_registry",
      "why": "YARA signature match for registry manipulation behavior, corroborates capa's registry-related findings and confirms malicious intent."
    },
    {
      "source": "YARA",
      "query_or_table": "matches",
      "row_or_rule": "escalate_priv",
      "why": "YARA signature match for privilege escalation behavior, indicates the sample attempts to gain elevated system access to bypass security controls, a malicious execution/defense evasion signal."
    },
    {
      "source": "FLOSS",
      "query_or_table": "strings",
      "row_or_rule": "AdjustTokenPrivileges, OpenProcessToken",
      "why": "Presence of token manipulation API strings confirms ability to adjust process token privileges, aligning with YARA's escalate_priv finding and confirming privilege escalation intent."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "Import of the RegSetValue API confirms native ability to modify registry values, aligning with capa and YARA registry manipulation findings."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_process (CreateProcess) [T1106]",
      "why": "Import of the CreateProcess API confirms ability to launch child processes, used for executing additional malicious payloads or system commands, a malicious execution capability."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "enumerate files on Windows (T1083)",
      "why": "Confirms ability to enumerate files on the host system, used to locate sensitive user data for exfiltration, a core infostealer behavior."
    },
    {
      "source": "Malcat",
      "query_or_table": "carved files",
      "row_or_rule": "NSIS@523776 (1055469 bytes)",
      "why": "Presence of a 1.05MB NSIS installer overlay in the file's overlay section indicates the sample is a bundled installer, a common delivery mechanism for malware payloads including infostealers."
    },
    {
      "source": "Malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "Certificate::Subject: Mozilla Corporation",
      "why": "The sample is signed with a code signing certificate issued to a legitimate software vendor (Mozilla) but exhibits clear malicious behavior, indicating the certificate is likely stolen for masquerading to avoid security detection, a common malware tactic."
    }
  ],
  "summary": "This is a malicious 32-bit Windows PE sample, identified as an NSIS installer/dropper for Lumma Stealer (infostealer). The sample is signed with a likely stolen code signing certificate issued to Mozilla Corporation to masquerade as legitimate software. Static analysis confirms multiple malicious behavioral capabilities: keylogging via polling, screen capture, registry enumeration and modification"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/prompt.txt` exists=`True` bytes=`30434` mtime=`2026-08-08T07:48:08.636175+00:00`
  - sha256: `40a32edbbc925d3ca78ebe5e3a67ab64206bafe4e44aece6c8511b25a9cb69a2`
- **verdict:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/verdict.json` exists=`True` bytes=`8420` mtime=`2026-08-08T07:49:09.853307+00:00`
  - sha256: `6c59a611e96614bdb04ae3ff3b88ffa5b1ca7a09c346878dda914cf61c505080`

#### prompt_excerpt

```
# Triage evidence
sha256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50
sample_path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe
ghidra_session: ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50
ida_session: ida-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA both report 172 imports (ghidra summary: imports=172; ida summary: imports=172), counts are within 20% threshold, Ghidra selected per existing rule.
- functions: ida (confidence=medium) — Ghidra reports 0 functions (ghidra summary: funcs=0) while IDA reports 97 (ida summary: funcs=97), IDA is the only source with valid function data per existing rule.
- strings: both (confidence=high) — Ghidra reports 180 strings, IDA reports 302 strings, Malcat reports 100 strings (ghidra summary: strings=180; ida summary
… [29395 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 87,
  "family_guess": "Lumma Stealer (infostealer) \u2014 sample is an NSIS installer/dropper for the Lumma payload, consistent with the sample filename and matching behavioral profile of keylogging, credential theft, registry manipulation, privilege escalation, and system enumeration.",
  "cross_engine_notes": [
    "Ghidra reports 0 functions and 0 imports, while IDA reports 97 functions and 172 imports, and Malcat reports 15 top functions and 172 imports. This discrepancy is caused by Ghidra failing to analyze the large (1.05MB) high-entropy NSIS overlay where the malicious payload resides; Ghidra's empty counts are a data analysis gap, not an indication of a benign sample.",
    "The sample is signed with a valid code signing certificate issued to Mozilla Corporation (valid 2025-01-09 to 2027-01-08), but exhibits clear malicious behavior, indicating the certificate is likely stolen for masquerading purposes to bypass security controls.",
    "
… [7420 more chars]
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
  "rule_count": 41,
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
      "name": "log keystrokes via polling",
      "attack": [
        {
          "parts": [
            "Collection",
            "Input Capture",
            "Keylogging"
          ],
          "tactic": "Collection",
          "technique": "Input Capture",
          "subtechnique": "Keylogging",
          "id": "T1056.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Collection",
            "Keylogging",
            "Polling"
          ],
          "objective": "Collection",
          "behavior": "Keylogging",
          "method": "Polling",
          "id": "F0002.002"
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
      "name": "query environment variable",
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
  
… [6543 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1142333,
  "duration_s": 0.04,
  "import_count": 171,
  "signal_count": 5,
  "signals": [
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
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 68179,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 51945,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 35044,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 26628,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 34204,
          "length": 58,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 779048,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a3",
          "offset": 1128685,
          "length": 140,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 192,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule":
… [6322 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2325,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".ndata",
    "@.reloc",
    "PWSVh@",
    "#Vhh2@",
    "Instu`",
    "softuW",
    "NulluN\tE",
    "SUVWj 3",
    "D$8PUh",
    "u}9-$.G",
    "[j0Xjxf",
    "D$$+D$",
    "D$4+D$,P",
    "PPPPPP",
    "\\u!f9O",
    "QSUVWh",
    "Ed+EL;E",
    "u$9Mls",
    ")Mh)Mlf",
    "]4;Mhr",
    "E89E0}s",
    "u$9Uls",
    "-)Uh)Ul3",
    "SHGetFolderPathW",
    "SHFOLDER",
    "SHAutoComplete",
    "SHLWAPI",
    "GetUserDefaultUILanguage",
    "AdjustTokenPrivileges",
    "LookupPrivilegeValueW",
    "OpenProcessToken",
    "RegDeleteKeyExW",
    "ADVAPI32",
    "MoveFileExW",
    "GetDiskFreeSpaceExW",
    "KERNEL32",
    "[Rename]",
    "Module32NextW",
    "Module32FirstW",
    "Process32NextW",
    "Process32FirstW",
    "CreateToolhelp32Snapshot",
    "Kernel32.DLL",
    "GetModuleBaseNameW",
    "EnumProcessModules",
    "EnumProcesses",
    "PSAPI.DLL",
    "MulDiv",
    "DeleteFileW",
    "FindFirstFileW",
    "FindNextFileW",
    "FindClose",
    "SetFilePointer",
    "MultiByteToWideChar",
    "ReadFile",
    "WriteFile",
    "lstrlenA",
    "WideCharToMultiByte",
    "GetPrivateProfileStringW",
    "WritePrivateProfileStringW",
    "FreeLibrary",
    "LoadLibraryExW",
    "GetModuleHandleW",
    "GlobalFree",
    "GetExitCodeProcess",
    "WaitForSingleObject",
    "GlobalAlloc",
    "ExpandEnvironmentStringsW",
    "lstrcmpW",
    "lstrcmpiW",
    "CloseHandle",
    "SetFileTime",
    "CompareFileTime",
    "SearchPathW",
    "GetShortPathNameW",
    "GetFullPathNameW",
    "MoveFileW"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2325
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 29.03,
  "size_bytes": 1142333,
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
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "disassembly": {
    "0x004039e3": "\u250c 997: entry0 ();\n\u2502           ; var int32_t var_10h_4 @ esp+0x10\n\u2502           ; var int32_t var_10h_3 @ esp+0x28\n\u2502           ; var int32_t var_30h @ esp+0x58\n\u2502           ; var int32_t var_2ch @ esp+0x60\n\u2502           ; var int32_t var_44h @ esp+0x6c\n\u2502           ; var int32_t var_24h @ esp+0x70\n\u2502           ; var int32_t var_10h_2 @ esp+0x74\n\u2502           ; var int32_t var_14h_2 @ esp+0x78\n\u2502           ; var int32_t var_18h_2 @ esp+0x7c\n\u2502           ; var int32_t var_14h_3 @ esp+0x90\n\u2502           ; var int32_t var_1ch @ esp+0x98\n\u2502           ; var int32_t var_10h @ esp+0xcc\n\u2502           ; var int32_t var_14h @ esp+0xd0\n\u2502           ; var int32_t var_18h @ esp+0xd4\n\u2502           ; var int32_t var_38h @ esp+0xe0\n\u2502           0x004039e3      81ecd4020000   sub esp, 0x2d4\n\u2502           0x004039e9      53             push ebx\n\u2502           0x004039ea      55             push ebp\n\u2502           0x004039eb      56             push esi\n\u2502           0x004039ec      57             push edi\n\u2502           0x004039ed      6a20           push 0x20                   ; 32\n\u2502           0x004039ef      33ed           xor ebp, ebp\n\u2502           0x004039f1      5e             pop esi\n\u2502           0x004039f2      896c2418       mov dword [var_18h], ebp\n\u2502           0x004039f6      c7442410d8..   mov dword [var_10h], str.Error_writing_temporary_file._Make_sure_your_temp_folder_is_valid. ; [0x4091d8:4]=0x720045 ; u\"Error writing temporary file. Make sure your temp folder is valid.\"\n\u2502           0x004039fe      896c2414       mov dword [var_14h], ebp\n\u2502           0x00403a02      ff1530804000   call dword [sym.imp.COMCTL32.dll_InitCommonControls] ; 0x408030 ; void InitCommonControls(void)\n\u2502           0x00403a08      6801800000     push 0x8001\n\u2502           0x00403a0d      ff15b8804000   call dword [sym.imp.KERNEL32.dll_SetErrorMode] ; 0x4080b8 ; UINT SetErrorMode(UINT uMode)\n\u2502           0x00403a13      55             push ebp\n\u2502           0x00403a14      ff15c0824000   call dword [sym.imp.ole32.dll_OleInitialize] ; 0x4082c0\n\u2502           0x00403a1a      6a08           push 8                      ; 8\n\u2502           0x00403a1c      a3b82e4700     mov dword [0x472eb8], eax   ; [0x472eb8:4]=0\n\u2502           0x00403a21      e8372a0000     call 0x40645d\n\u2502           0x00403a26      55             push ebp\n\u2502           0x00403a27      68b4020000     push 0x2b4                  ; 692\n\u2502           0x00403a2c      a3d02d4700     mov dword [0x472dd0], eax   ; [0x472dd0:4]=0\n\u2502           0x00403a31      8d442438       lea eax, [var_38h]\n\u2502           0x00403a35      50             push eax\n\u2502           0x00403a36      55             push ebp\n\u2502           0x00403a37      681c934000     push 0x40931c\n\u2502           0x00403a3c      ff1584814000   call dword [sym.imp.SHELL32.dll_SHGetFileInfoW] ; 0x408184 ; DWORD_PTR SHGetFileInfoW(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags)\n\u2502           0x00403a42      6804934000     push str.NSIS_Error         ; 0x409304 ; u\"NSIS Error\"\n\u2502           0x00403a47  "
  },
  "engine": "pdf (disasm)",
  "fallba
… [60 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!SetFileTime",
      "KERNEL32.dll!CompareFileTime",
      "KERNEL32.dll!SearchPathW",
      "KERNEL32.dll!GetShortPathNameW",
      "KERNEL32.dll!GetFullPathNameW",
      "USER32.dll!GetAsyncKeyState",
      "USER32.dll!IsDlgButtonChecked",
      "USER32.dll!ScreenToClient",
      "USER32.dll!GetMessagePos",
      "USER32.dll!CallWindowProcW",
      "GDI32.dll!SetBkColor",
      "GDI32.dll!GetDeviceCaps",
      "GDI32.dll!DeleteObject",
      "GDI32.dll!CreateBrushIndirect",
      "GDI32.dll!CreateFontIndirectW",
      "SHELL32.dll!SHBrowseForFolderW",
      "SHELL32.dll!SHGetPathFromIDListW",
      "SHELL32.dll!SHGetFileInfoW",
      "SHELL32.dll!ShellExecuteW",
      "SHELL32.dll!SHFileOperationW",
      "ADVAPI32.dll!RegEnumKeyW",
      "ADVAPI32.dll!RegOpenKeyExW",
      "ADVAPI32.dll!RegCloseKey",
      "ADVAPI32.dll!RegDeleteKeyW",
      "ADVAPI32.dll!RegDeleteValueW",
      "COMCTL32.dll!ImageList_AddMasked",
      "COMCTL32.dll!ImageList_Destroy",
      "COMCTL32.dll!ImageList_Create",
      "ole32.dll!CoTaskMemFree",
      "ole32.dll!OleInitialize"
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
  "checked": 4,
  "hits": 4,
  "misses": [],
  "hit_examples": [
    "IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDigitalSignature, Nullsoft_PiMP_Stub_SFX PE and packaging characteristics",
    "domain, IP, url, contains_base64 C2 communication indicators Hardcoded domain, IPv4/IPv6 addresses, URL, and base64 stri",
    "escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation Malicious capability indicators YARA ",
    "Sample path /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.e"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 50,
  "summary": "The analyzed sample is a packed, digitally signed Windows GUI PE executable (identified as Lumma info-stealer via sample path metadata) with a Nullsoft PiMP self-extracting (SFX) stub. It contains indicators of C2 communication (hardcoded domain, IPv4/IPv6 addresses, URL, and base64 strings) and imp",
  "key_evidence": [
    {
      "source": "yara_scan_findings",
      "query_or_table": "PE and packaging characteristics",
      "row_or_rule": "IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDigitalSignature, Nullsoft_PiMP_Stub_SFX",
      "why": "Confirms the sample is a packed Windows GUI PE executable with an overlay, valid digital signature, and Nullsoft self-extracting stub, common traits for malware distribution to evade detection and simplify execution."
    },
    {
      "source": "yara_scan_findings",
      "query_or_table": "C2 communication indicators",
      "row_or_rule": "domain, IP, url, contains_base64",
      "why": "Hardcoded domain, IPv4/IPv6 addresses, URL, and base64 strings were detected in the sample, which are typical indicators of command-and-control (C2) communication functionality in malware."
    },
    {
      "source": "yara_scan_findings",
      "query_or_table": "Malicious capability indicators",
      "row_or_rule": "escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation",
      "why": "YARA rules matched for all common info-stealer and post-exploitation capabilities, confirming the sample is designed to perform malicious actions on infected systems including stealing data and maintaining access."
    },
    {
      "source": "yara_scan_findings",
      "query_or_table": "Sample identification",
      "row_or_rule": "Sample path /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "why": "The sample filename explicitly identifies it as a Lumma info-stealer, a known publicly available malware family focused on stealing credentials, session data, and other sensitive information from Windows systems."
    }
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
      "path": "/opt/
… [9422 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "file_name": "lumma_sample.exe",
    
… [89591 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 41,
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
… [9643 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1142333,
  "duration_s": 0.04,
  "import_count": 171,
  "signal_count": 5,
  "signals": [
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
      "la
… [417 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2325,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".ndata",
    "@.reloc",
    "PWSVh@",
    "#Vhh2@",
    "Instu`",
    "softuW",
    "NulluN\tE",
    "SUVWj 3",
    "D$8PUh",
    "u}9-$.G",
    "[j0Xjxf",
    "D$$+D$",
    "D$4+D$,P",
    "PPPPPP",
    "\\u!f9O",
    "QSUVWh",
   
… [1673 more chars]
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
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "disassembly": {
    "0x004039e3": "\u250c 997: entry0 ();\n\u2502           ; var int32_t var_10h_4 @ esp+0x10\n\u2502           ; var int32_t var_10h_3 @ esp+0x28\n\u2502           ; var int32_t var_30h @ esp+0x58\n\u2502           ; var int32_t var_2
… [3160 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xor
… [23 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!SetFileTime",
      "KERNEL32.dll!CompareFileTime",
      "KERNEL32.dll!SearchPathW",
      "KERNEL32.dll!GetShortPathNameW",
      "K
… [951 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — Auto SQL seed for large-mode deep RE gate

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
  "source": "ghidra_query",
  "session_id": "ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "audit_path": "/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/audit.jsonl"
}
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
      "name": "RegCloseKey",
      "module": "ADVAPI32.DLL",
      "address": "155"
    },
    {
      "name": "RegCreateKeyExW",
      "module": "ADVAPI32.DLL",
      "address": "158"
    },
    {
      "name": "RegDeleteKeyW",
      "module": "ADVAPI32.DLL",
      "address": "156"
    },
    {
      "name": "RegDelet
… [1377 more chars]
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
      "content": "ADVAPI32.dll",
      "address": "4237722",
      "length": "13"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "audit_path": "/opt/samples/logs/706
… [76 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [
    {
      "name": "RegCloseKey",
      "module": "ADVAPI32",
      "address": "4227080"
    },
    {
      "name": "RegCreateKeyExW",
      "module": "ADVAPI32",
      "address": "4227092"
    },
    {
      "name": "RegDeleteKeyW",
      "module": "ADVAPI32",
      "address": "4227084"
    },
    {
      "name": "RegDelet
… [1372 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/01-tools-raw.json` exists=`True` bytes=`129208` mtime=`2026-08-08T07:49:52.860161+00:00`
  - sha256: `1ee941e584304f8cec33d4dc129ed7ba8e71d5abf938757cdbfa2de1d229834f`
- **sql_evidence:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/05-deep-dive.json` exists=`True` bytes=`6177` mtime=`2026-08-08T07:51:42.800212+00:00`
  - sha256: `98cadd39125d170b3d0957b7e36ba92c8a872be22a88351f574869f6c31d5599`

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
  "verdict": "Malicious",
  "confidence": 50,
  "summary": "The analyzed sample is a packed, digitally signed Windows GUI PE executable (identified as Lumma info-stealer via sample path metadata) with a Nullsoft PiMP self-extracting (SFX) stub. It contains indicators of C2 communication (hardcoded domain, IPv4/IPv6 addresses, URL, and base64 strings) and implements multiple malicious post-exploitation and info-stealing capabilities including privilege escalation, screenshot capture, keylogging, Windows token manipulation, registry modification, and file system operations.\nPersistence: Not observed, no persistence mechanisms (e.g., registry Run key modifications, scheduled task creation, startup folder placement) were identified d
… [5377 more chars]
```

- **agentic:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`314034` mtime=`2026-08-08T07:51:42.799212+00:00`
  - sha256: `23dff6a02e545b068c40edddbc678ec4cd1e9425c9bbdf2dd5f687996d8fefee`

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

- **rule_yar:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/rule.yar` exists=`True` bytes=`1159` mtime=`2026-08-08T07:51:45.958205+00:00`
  - sha256: `d70beaec01a76035ed55f3f0be7d9d5d8409b8bb07666963bc7285de1da5d629`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T07:51:45.958780+00:00
rule CADRE_v2_unknown_706a49b55ba7 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "WritePrivateProfileStringW" ascii wide
        $s1 = "SHGetSpecialFolderLocation" ascii wide
        $s2 = "ExpandEnvironmentStringsW" ascii wide
        $s3 = "GetPrivateProfileStringW" ascii wide
        $s4 = "GetFileVersionInfoSizeW" ascii wide
        $s5 = "SystemParametersInfoW" ascii wide
        $s6 = "SetCurrentDirec
… [357 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-MASTER-v2.md` exists=`True` bytes=`24439` mtime=`2026-08-08T08:28:07.451540+00:00`
  - sha256: `85d2256687ceb17cde93182d2bcd3dbca600413c4a972a00210ba7e63b7a8fb1`
- **REPORT_MASTER_v3:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-MASTER-v3.md` exists=`True` bytes=`49748` mtime=`2026-08-08T08:03:13.830963+00:00`
  - sha256: `6190eebeadf164cdda9c9a434886bffea526aa1ac5f64427cd0c455ffa407477`
- **REPORT_v2:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-v2.md` exists=`True` bytes=`24439` mtime=`2026-08-08T08:28:07.451540+00:00`
  - sha256: `85d2256687ceb17cde93182d2bcd3dbca600413c4a972a00210ba7e63b7a8fb1`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`93751` mtime=`2026-08-08T08:30:56.920469+00:00`
  - sha256: `19a5195e780265ec836664291a51ea3f3e4c93d069e4a31ee2d0618c29096ec7`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`70856` mtime=`2026-08-08T08:05:27.544006+00:00`
  - sha256: `9de9a1eb763b8483cd709608da43178664f9cf8fb140bdea4a5471365c937766`
- **report_v2_json:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/report-v2.json` exists=`True` bytes=`27404` mtime=`2026-08-08T08:30:56.925469+00:00`
  - sha256: `61f74d5625a1da98db741328b878f464576a260c8c378d37bb1de9f051a38bc8`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 08:28:07 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | Malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Lumma Stealer (infostealer) — sample is an NSIS installer/dropper for the Lumma payload, consistent with the sample filename and matching behavioral profile of keylogging, credential theft, regis
… [23526 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 08:03:13 UTC

# RE Report — 706a49b55ba7
_Generated 2026-08-08T08:03:13.822883+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=485c | cross_refs=True | llm_ok=True | runtime=55.07s -->

# Executive Summary

Sample SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`

| Core Metric | Value | Supporting Evidence & Confidence |
|-------------|-------|----------------------------------|
| Final Verdict | Malicious | High confidence: aligned across both the LLM judge and legacy v1 scanner, with a v1 scanner score of 290 driven by 19 YARA signa
… [48835 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
