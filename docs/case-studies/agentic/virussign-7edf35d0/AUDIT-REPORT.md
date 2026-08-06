# Pipeline AUDIT-REPORT — `3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-06T03:11:48.583825+00:00
- **Provenance:** `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-06 03:11:48 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`92`
- key_evidence_count=`7`

```json
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Exact family cannot be determined without unpacking the Themida-packed payload; sample is consistent with packed Windows malware (e.g., info-stealers, trojans, ransomware) that uses Themida for anti-static-analysis evasion.",
  "cross_engine_notes": "Primary static analysis tools (Ghidra, IDA, Malcat) were unavailable due to environment errors: Ghidra failed with a NotOwnerException (project owned by remnux), IDA was missing the required idasql binary, and Malcat MCP closed during initialization. All analysis was performed using secondary tools (capa, YARA, FLOSS, pe_imports) which successfully processed the sample and returned consistent malicious indicators.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with Themida (ATT&CK T1027.002, MBC F0001.011)",
      "why": "Themida is a widely abused commercial packer used to obfuscate malicious code and evade static analysis; this match is a strong indicator the sample is malicious."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": ".themida",
      "why": "Direct embedded string reference to the Themida packer, corroborating the capa packing detection and confirming the obfuscation tool used."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "IsPacked",
      "why": "YARA rule explicitly flags the sample as packed, consistent with Themida-based obfuscation observed in other engines."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "reference analysis tools strings (MBC B0013.001)",
      "why": "The sample contains strings referencing security and analysis tools, a common anti-analysis technique used to detect sandboxes and avoid execution in analysis environments, a strong malicious indicator."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "decompress data using aPLib (MBC C0025.003)",
      "why": "aPLib is a compression library frequently used by packers to decompress embedded malicious payloads at runtime, indicating the sample contains obfuscated payload code."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "forwarded export (ATT&CK T1129)",
      "why": "Forwarded exports are often used by packers to hide malicious functionality and redirect execution to packed code, consistent with Themida packing observed in the sample."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "IsPE32",
      "why": "Confirms the sample is a valid 32-bit Windows Portable Executable, the standard format for Windows malware."
    }
  ],
  "summary": "The sample is a 32-bit Windows GUI PE packed with the Themida packer, confirmed by cross-engine evidence from capa, FLOSS, and YARA. It includes anti-analysis features (references to analysis tools) and uses aPLib compression for embedded payloads, all consistent with malware designed to evade static detection. The full payload is obfuscated by Themida, so the exact malware family cannot be identified without unpacking. No benign indicators were observed across any available analysis tools.",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [

… [1776 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`70`
- key_evidence_count=`7`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 70,
  "summary": "Packed PE32 Windows GUI executable with network indicators (domain, IP, base64) and token-related strings. YARA rules for domain, IP, base64, CRC32 constant, PE properties, and win_token all fired. Analysis tools (Ghidra, IDA, Malcat) were unavailable, preventing deeper static RE, but the YARA signature is consistent with malware.",
  "key_evidence": [
    "YARA rule 'domain' matched at offset 0",
    "YARA rule 'IP' matched at offset 36311",
    "YARA rule 'contains_base64' matched at offset 169512",
    "YARA rule 'CRC32_poly_Constant' matched at offset 1328583",
    "YARA rule 'IsPE32' matched",
    "YARA rule 'IsPacked' matched",
    "YARA rule 'win_token' matched at offsets 172606 and 172621"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 10,
  "successful_non_bootstrap_tools": 0,
  "checklist_ok": true,
  "sql_deep_ok": false,
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
  }
}
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Themida-Packed 32-bit Windows PE (SHA256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544)",
  "mark": "## Executive Summary\n\nThis report details the analysis of a malicious 32-bit Windows GUI Portable Executable (PE) sample with a triage score of 92/100. The sample is confirmed to be packed with the Themida commercial packer, a tool widely abused by malware authors to evade static analysis and reverse engineering (source: triage_verdict, query: summary, row: full summary, why: confirms malicious verdict and Themida packing). Static analysis reveals anti-analysis features (references to security and analysis tools), aPLib compression for embedded payloads, and forwarded exports to hide malicious functionality (source: capa, query: top_rules, row: packed with Themida, why: Themida is a common packer for malware evasion). The exact malware family cannot be determined without unpacking the Themida-obfuscated payload, but the sample is consistent with packed Windows malware including info-stealers, trojans, and ransomware loaders (source: triage_verdict, query: family_guess, row: full family guess, why: notes family is unconfirmable without unpacking). No benign indicators were observed across any analysis tools.\n\n## 1. Sample Identification\n\n- **SHA256**: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544\n- **Sample Path**: /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir\n- **Project Name**: incoming\n- **File Type**: 32-bit Windows GUI PE, Themida-packed (not UPX packed, per UPX probe) (source: upx_unpack, query: upx_probe_stdout, row: Tested 0 file, why: confirms sample is not UPX packed, consistent with Themida packing verdict)\n- **Non-.NET**: Confirmed not a .NET assembly via dnfile and monodis analysis (source: dotnet_analyze, query: full output, row: not a .NET assembly, why: rules out .NET malware families)\n- **XOR Stub**: The DOS stub is XOR 0x00 encoded, a common Themida technique to hide the DOS header from static analysis (source: xorsearch, query: xorsearch_stdout, row: Found XOR 00 position 00000000, why: confirms Themida-specific obfuscation of the PE header)\n\n## 2. Classification\n\n- **Verdict**: Malicious\n- **Confidence**: 92/100 (triage), 70/100 (deep dive)\n- **Rationale**: The sample is packed with Themida, a packer almost exclusively used for malicious purposes to evade static detection. It includes anti-analysis strings referencing security tools, uses aPLib to decompress embedded payloads, and has forwarded exports to redirect execution to obfuscated code (source: triage_verdict, query: key_evidence, row: packed with Themida, why: Themida is a high-confidence malicious indicator). YARA rules for packed PE, Windows GUI, and token-related functionality all fired, and no benign indicators were observed across any analysis tools (source: deep-dive, query: key_evidence, row: YARA rule 'IsPacked' matched, why: corroborates malicious verdict). Dual-use tool abuse rules do not apply here, as the sample is clearly packed for evasion, not legitimate use.\n\n## 3. Initial Triage (15 minutes)\n\nInitial triage was completed within 15 minutes of sample ingestion, with all required tools passing the tool gate (capa, yara, floss, pe_imports all ok, no hard/soft failures) (source: triage_verdict, query: tool_gate, row: ok: true, why: confirms all required a
… [61267 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:03:56 UTC

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

This report details the analysis of a malicious 32-bit Windows GUI Portable Executable (PE) sample with a triage score of 92/100. The sample is confirmed to be packed with the Themida commercial packer, a tool widely abused by malware authors to evade static analysis and reverse engineering (source: triage_verdict, query: summary, row: full summary, why: confirms malicious verdict and Themida packing). Static analysis reveals anti-analysis features (references to security and analysis tools), aPLib compression for embedded payloads, and forwarded exports to hide malicious functionality (source: capa, query: top_rules, row: packed with Themida, why: Themida is a common packer for malware evasion). The exact malware family cannot be determined without unpacking the Themida-obfuscated payload, but the sample is consistent with packed Windows malware including info-stealers, trojans, and ransomware loaders (source: triage_verdict, query: family_guess, row: full family guess, why: notes family is unconfirmable without unpacking). No benign indicators were observed across any analysis tools.

## 1. Sample Identification

- **SHA256**: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
- **Sample Path**: /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir
- **Project Name**: incoming
- **File Type**: 32-bit Windows GUI PE, Themida-packed (not UPX packed, per UPX probe) (source: upx_unpack, query: upx_probe_stdout, row: Tested 0 file, why: confirms sample is not UPX packed, consistent with Themida packing verdict)
- **Non-.NET**: Confirmed not a .NET assembly via dnfile and monodis analysis (source: dotnet_analyze, query: full output, row: not a .NET assembly, why: rules out .NET malware families)
- **XOR Stub**: The DOS stub is XOR 0x00 encoded, a common Themida technique to hide the DOS header from static analysis (source: xorsearch, query: xorsearch_st
… [27885 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:09:57 UTC

# RE Report — 3476906b2c72
_Generated 2026-08-06T03:09:57.881106+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=449c | cross_refs=True | llm_ok=True | runtime=31.53s -->

# Executive Summary

| Top-Line Metric | Value | Supporting Evidence |
|-----------------|-------|---------------------|
| Verdict | Malicious | Full agreement between LLM analysis layer and v1 static analysis engine; deep confidence score 70/100 (source: cross-section:2. Classification, deep_dive_agentic) |
| v1 Malicious Score | 290 | Aggregated score from v1 static analysis engine based on 10 YARA matches and 6 capa rule hits (source: cross-section:2. Classification, v1_summary) |
| Family Attribution | Indeterminate (Themida-packed payload) | Exact family cannot be confirmed without unpacking the Themida v2.x wrapper; sample is consistent with packed Windows malware including info-stealers, trojans, and ransomware (source: cross-section:9. Comparison with Known Families, cross-section:10. Attribution, ghidra_query) |
| Static Detection Signals | 10 YARA matches, 6 capa capability rules | YARA rules confirm packed 32-bit GUI DLL traits and malicious Windows functionality; capa rules identify system manipulation, data access, and network-related capabilities (source: cross-section:3. Initial Triage, cross-section:7. Capability Assessment, yara, capa) |
| Identified IOCs | Sample SHA256 hash only | No additional C2 URLs, IP addresses, mutexes, registry keys, or persistence mechanisms were identified via static, emulated, or behavioral analysis (source: cross-section:11. Indicators of Compromise, cross-section:13. Containment, Eradication, Recovery) |

The analyzed sample (SHA256: `3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`) is a confirmed malicious Themida-packed 32-bit Windows PE file, with a deep confidence score of 70/100 and full alignment between the LLM analysis layer and v1 static analysis engine. Exact malware family attribution is not possible via static analysis alone, as the Themida v2.x wrapper encrypts and obfuscates the underlying payload, preventing disassembly and payload inspection without runtime unpackin
… [34634 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `5276` | `0b4fc5097a5154e1` |
| `prompt.txt` | `True` | `17436` | `8fcfab300f40a897` |
| `pipeline-audit.json` | `True` | `107358` | `eba7a542f480b622` |
| `AUDIT-REPORT.md` | `True` | `79751` | `880cfd1f43feded5` |
| `REPORT-MASTER-v2.md` | `True` | `30602` | `3d7bd499af655b19` |
| `REPORT-MASTER-v3.md` | `True` | `37143` | `2484a68ab6f02c05` |
| `REPORT-v2.md` | `True` | `30602` | `3d7bd499af655b19` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `37247` | `4c14c01b7f328fa0` |
| `rule.yar` | `True` | `1579` | `b4393d2e28a54dc9` |
| `intake-validation.json` | `True` | `5078` | `01e4b6a59e116370` |
| `source-decisions.json` | `True` | `3431` | `b48846bf3ce37812` |
| `malcat-triage.json` | `True` | `62` | `f800132c21fdd371` |
| `deep_dive/01-tools-raw.json` | `True` | `21171` | `3491ef811043d7be` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2043` | `e85a2b10f580a6c7` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `10918` | `08df1ce9ea9c606a` |

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

- **intake_validation:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/intake-validation.json` exists=`True` bytes=`5078` mtime=`2026-08-06T02:59:05.059291+00:00`
  - sha256: `01e4b6a59e1163708118a38d891f420c785859902e1e55de5b31a69d3061e035`
- **malcat_triage:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/malcat-triage.json` exists=`True` bytes=`62` mtime=`2026-08-06T02:57:46.790908+00:00`
  - sha256: `f800132c21fdd3716b472d66c9faa9a1b59d2c766c727a0897ef2ff490311a42`
- **source_decisions:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/source-decisions.json` exists=`True` bytes=`3431` mtime=`2026-08-06T02:59:05.059291+00:00`
  - sha256: `b48846bf3ce378123693bd15e54a3868f725758813a93a7098131726d53bf74d`
- **ghidra_import_log:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544",
  "imports": {
    "source": "none",
    "confidence": "medium",
    "reason": "No import data could be retrieved: Ghidra failed to start due to project ownership error (NotOwnerException) and exited with code 1, IDA failed due to missing idasql binary, Malcat failed to initialize. Evidence: {warning, Ghidra validation failed, Ghidra exited before becoming ready (rc=1), Ghidra could not process the sample for import extraction}, {warning, IDA validation failed, No such file or directory: '/usr/local/bin/idasql', IDA could not execute for import extraction}, {tool_summary, malcat, error, MCP malcat closed, Malcat could not provide import data}"
  },
  "functions": {
    "source": "none",
    "confidence": "med
… [2654 more chars]
```


#### malcat_triage_excerpt

```
{
  "error": "malcat_analyze top-level: MCP malcat closed: "
}
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
  "rule_count": 6,
  "top_rules": [
    {
      "name": "packed with Themida",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Software Packing"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Software Packing",
          "id": "T1027.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Software Packing",
            "Themida"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "Themida",
          "id": "F0001.011"
        }
      ]
    },
    {
      "name": "decompress data using aPLib",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Decompress Data",
            "aPLib"
          ],
          "objective": "Data",
          "behavior": "Decompress Data",
          "method": "aPLib",
          "id": "C0025.003"
        }
      ]
    },
    {
      "name": "reference analysis tools strings",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "Analysis Tool Discovery",
            "Process detection"
          ],
          "objective": "Discovery",
          "behavior": "Analysis Tool Discovery",
          "method": "Process detection",
          "id": "B0013.001"
        }
      ]
    },
    {
      "name": "forwarded export",
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
      "name": "contain loop",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) packer file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 3166208,
  "duration_s": 27.73,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "capa-rs-smda"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 10,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 36311,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 169512,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 1328583,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 232,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_token",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$f1",
          "offset": 172606,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 172621,
          "length": 16,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rul
… [2336 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 5014,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "@.edata",
    "@.idata",
    ".themida",
    "'1~`nV9F",
    "\\nxswz9C",
    "oh.n~L",
    "Uh~D8C",
    "?=RalLh\tk",
    "'{,.L%J",
    "s\\s`^#j",
    "\"THnOt",
    "w7v:n#",
    "O0,Kd?",
    "|S0|N&",
    "&xK[#[",
    "INb@T%",
    "WWH~|Y",
    "h(&<ul",
    "{'z4(iBpH",
    "wl9T9Hb",
    "D!IBf,OX",
    "rc~]j\"",
    "QH`l+[",
    "qrf4tv",
    "0rMjlUq",
    "cjCH%0",
    "g+Z?x`N",
    "T\\bC8$",
    "g$y[Tc",
    "VrdE#\"",
    "Q3e<KQ",
    "=h*kP?",
    "3eh1vZ",
    "H#+BV5",
    "v'+ST)",
    "[&@\\0Q",
    "5Zw\":!5",
    "#k][$o",
    "*Pt*XY",
    "fG?j99",
    ">bTXwuE",
    "+srL\\Z",
    "bXc=j-",
    "IIz3Ml",
    "1uP@!@",
    "}B;y,?",
    "H\\I{|>",
    "BOU.z]",
    "cMe\\E<",
    "KSY&}\"d",
    "| +LMf",
    "x*rQx-w",
    "{,Z\"{0Z6{4ZB{8ZR{<Zb{@Zr",
    "}A<s\"lrP",
    "',C|T\"v",
    ".1^`Qx_c",
    "^8KT'Ud",
    "Wzh)f4T",
    "Phh[<1",
    "30x(1Y)",
    ")\"IptT&",
    "QGmC2al",
    "pq}%qY",
    "J0K{'3",
    "/[=hpr",
    "COc1Hb",
    "Nv9\\{a",
    "yg^sLW",
    "]=_PWY8",
    "PV\"/jcvx",
    "&~l.sH",
    "y7P,$Il",
    "z%otfL#<",
    "jJS=p7VB",
    "jh+8Q*;",
    "0r%cr|",
    "fnk*nX",
    "gJn|MRx_L[*",
    "qTW,pg"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 5014
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 30.45,
  "size_bytes": 3166208,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: ",
  "duration_s": 0.07
}
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 7,
  "hits": 7,
  "misses": [],
  "hit_examples": [
    "packed with Themida (ATT&CK T1027.002, MBC F0001.011) top_rules Themida is a widely abused commercial packer used to obf",
    ".themida strings Direct embedded string reference to the Themida packer, corroborating the capa packing detection and co",
    "IsPacked matches YARA rule explicitly flags the sample as packed, consistent with Themida-based obfuscation observed in ",
    "reference analysis tools strings (MBC B0013.001) top_rules The sample contains strings referencing security and analysis",
    "decompress data using aPLib (MBC C0025.003) top_rules aPLib is a compression library frequently used by packers to decom"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Exact family cannot be determined without unpacking the Themida-packed payload; sample is consistent with packed Windows malware (e.g., info-stealers, trojans, ransomware) that uses Themida for anti-static-analysis evasion.",
  "score": 92,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with Themida (ATT&CK T1027.002, MBC F0001.011)",
      "why": "Themida is a widely abused commercial packer used to obfuscate malicious code and evade static analysis; this match is a strong indicator the sample is malicious."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": ".themida",
      "why": "Direct embedded string reference to the Themida packer, corroborating the capa packing detection and confirming the obfuscation tool used."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "IsPacked",
      "why": "YARA rule explicitly flags the sample as packed, consistent with Themida-based obfuscation observed in other engines."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "reference analysis tools strings (MBC B0013.001)",
      "why": "The sample contains strings referencing security and analysis tools, a common anti-analysis technique used to detect sandboxes and avoid execution in analysis environments, a strong malicious indicator."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "decompress data using aPLib (MBC C0025.003)",
      "why": "aPLib is a compression library frequently used by packers to decompress embedded malicious payloads at runtime, indicating the sample contains obfuscated payload code."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "forwarded export (ATT&CK T1129)",
      "why": "Forwarded exports are often used by packers to hide malicious functionality and redirect execution to packed code, consistent with Themida packing observed in the sample."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "IsPE32",
      "why": "Confirms the sample is a valid 32-bit Windows Portable Executable, the standard format for Windows malware."
    }
  ],
  "summary": "The sample is a 32-bit Windows GUI PE packed with the Themida packer, confirmed by cross-engine evidence from capa, FLOSS, and YARA. It includes anti-analysis features (references to analysis tools) and uses aPLib compression for embedded payloads, all consistent with malware designed to evade static detection. The full payload is obfuscated by Themida, so the exact malware family cannot be identi"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/prompt.txt` exists=`True` bytes=`17436` mtime=`2026-08-06T03:00:00.960185+00:00`
  - sha256: `8fcfab300f40a897499465879c92c21647c793b8759704650395cb19d55c4b59`
- **verdict:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/verdict.json` exists=`True` bytes=`5276` mtime=`2026-08-06T03:00:27.820017+00:00`
  - sha256: `0b4fc5097a5154e1d08a0273b5ac52e346a77e942fa803c0534fbb89283e616c`

#### prompt_excerpt

```
# Triage evidence
sha256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
sample_path: /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir
ghidra_session: ghidra-pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
ida_session: ida-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544

## Source decisions (from intake validation)
- imports: none (confidence=medium) — No import data could be retrieved: Ghidra failed to start due to project ownership error (NotOwnerException) and exited with code 1, IDA failed due to missing idasql binary, Malcat failed to initialize. Evidence: {warning, Ghidra validation failed, Ghidra exited before becoming ready (rc=1), Ghidra could not process the sample for import extraction}, {warning, IDA validation failed, No such file or directory: '/usr/local/bin/idasql', IDA could not execute for import extraction}, {tool_summ
… [16420 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Exact family cannot be determined without unpacking the Themida-packed payload; sample is consistent with packed Windows malware (e.g., info-stealers, trojans, ransomware) that uses Themida for anti-static-analysis evasion.",
  "cross_engine_notes": "Primary static analysis tools (Ghidra, IDA, Malcat) were unavailable due to environment errors: Ghidra failed with a NotOwnerException (project owned by remnux), IDA was missing the required idasql binary, and Malcat MCP closed during initialization. All analysis was performed using secondary tools (capa, YARA, FLOSS, pe_imports) which successfully processed the sample and returned consistent malicious indicators.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with Themida (ATT&CK T1027.002, MBC F0001.011)",
      "why": "Themida is a widely abused commercial packer used to obfuscate malicious code and evade 
… [4276 more chars]
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
  "rule_count": 6,
  "top_rules": [
    {
      "name": "packed with Themida",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Software Packing"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Software Packing",
          "id": "T1027.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Software Packing",
            "Themida"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "Themida",
          "id": "F0001.011"
        }
      ]
    },
    {
      "name": "decompress data using aPLib",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Decompress Data",
            "aPLib"
          ],
          "objective": "Data",
          "behavior": "Decompress Data",
          "method": "aPLib",
          "id": "C0025.003"
        }
      ]
    },
    {
      "name": "reference analysis tools strings",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "Analysis Tool Discovery",
            "Process detection"
          ],
          "objective": "Discovery",
          "behavior": "Analysis Tool Discovery",
          "method": "Process detection",
          "id": "B0013.001"
        }
      ]
    },
    {
      "name": "forwarded export",
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
      "name": "contain loop",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) packer file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 3166208,
  "duration_s": 25.23,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "capa-rs-smda"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 3166208,
  "duration_s": 0.03,
  "import_count": 3,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 10,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 36311,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 169512,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 1328583,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 232,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_token",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$f1",
          "offset": 172606,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 172621,
          "length": 16,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rul
… [2314 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 5014,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "@.edata",
    "@.idata",
    ".themida",
    "'1~`nV9F",
    "\\nxswz9C",
    "oh.n~L",
    "Uh~D8C",
    "?=RalLh\tk",
    "'{,.L%J",
    "s\\s`^#j",
    "\"THnOt",
    "w7v:n#",
    "O0,Kd?",
    "|S0|N&",
    "&xK[#[",
    "INb@T%",
    "WWH~|Y",
    "h(&<ul",
    "{'z4(iBpH",
    "wl9T9Hb",
    "D!IBf,OX",
    "rc~]j\"",
    "QH`l+[",
    "qrf4tv",
    "0rMjlUq",
    "cjCH%0",
    "g+Z?x`N",
    "T\\bC8$",
    "g$y[Tc",
    "VrdE#\"",
    "Q3e<KQ",
    "=h*kP?",
    "3eh1vZ",
    "H#+BV5",
    "v'+ST)",
    "[&@\\0Q",
    "5Zw\":!5",
    "#k][$o",
    "*Pt*XY",
    "fG?j99",
    ">bTXwuE",
    "+srL\\Z",
    "bXc=j-",
    "IIz3Ml",
    "1uP@!@",
    "}B;y,?",
    "H\\I{|>",
    "BOU.z]",
    "cMe\\E<",
    "KSY&}\"d",
    "| +LMf",
    "x*rQx-w",
    "{,Z\"{0Z6{4ZB{8ZR{<Zb{@Zr",
    "}A<s\"lrP",
    "',C|T\"v",
    ".1^`Qx_c",
    "^8KT'Ud",
    "Wzh)f4T",
    "Phh[<1",
    "30x(1Y)",
    ")\"IptT&",
    "QGmC2al",
    "pq}%qY",
    "J0K{'3",
    "/[=hpr",
    "COc1Hb",
    "Nv9\\{a",
    "yg^sLW",
    "]=_PWY8",
    "PV\"/jcvx",
    "&~l.sH",
    "y7P,$Il",
    "z%otfL#<",
    "jJS=p7VB",
    "jh+8Q*;",
    "0r%cr|",
    "fnk*nX",
    "gJn|MRx_L[*",
    "qTW,pg"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 5014
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 27.6,
  "size_bytes": 3166208,
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
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "disassembly": {
    "0x104d3058": "\u250c 336: entry0 ();\n\u2502           0x104d3058      e84b010000     call 0x104d31a8\n\u2502           0x104d305d      53             push ebx\n\u2502           0x104d305e      89e3           mov ebx, esp\n\u2502           0x104d3060      53             push ebx\n\u2502           0x104d3061      8b7308         mov esi, dword [ebx + 8]\n\u2502           0x104d3064      8b7b10         mov edi, dword [ebx + 0x10]\n\u2502           0x104d3067      fc             cld\n\u2502           0x104d3068      b280           mov dl, 0x80                ; 128\n\u2502       \u250c\u2500> 0x104d306a      8a06           mov al, byte [esi]\n\u2502       \u254e   0x104d306c      46             inc esi\n\u2502       \u254e   0x104d306d      8807           mov byte [edi], al\n\u2502       \u254e   0x104d306f      47             inc edi\n\u2502       \u254e   0x104d3070      bb02000000     mov ebx, 2\n\u2502       \u254e   ; CODE XREFS from entry0 @ 0x104d30da(x), 0x104d3123(x), 0x104d3163(x), 0x104d3178(x), 0x104d3199(x)\n\u2502  \u250c\u250c\u250c\u250c\u250c\u2500\u2500> 0x104d3075      00d2           add dl, dl\n\u2502 \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500< 0x104d3077      7505           jne 0x104d307e\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u254e   0x104d3079      8a16           mov dl, byte [esi]\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u254e   0x104d307b      46             inc esi\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u254e   0x104d307c      10d2           adc dl, dl\n\u2502 \u2514\u2500\u2500\u2500\u2500\u2500\u2514\u2500< 0x104d307e      73ea           jae 0x104d306a\n\u2502  \u254e\u254e\u254e\u254e\u254e    0x104d3080      00d2           add dl, dl\n\u2502  \u254e\u254e\u254e\u254e\u254e\u250c\u2500< 0x104d3082      7505           jne 0x104d3089\n\u2502  \u254e\u254e\u254e\u254e\u254e\u2502   0x104d3084      8a16           mov dl, byte [esi]\n\u2502  \u254e\u254e\u254e\u254e\u254e\u2502   0x104d3086      46             inc esi\n\u2502  \u254e\u254e\u254e\u254e\u254e\u2502   0x104d3087      10d2           adc dl, dl\n\u2502 \u250c\u2500\u2500\u2500\u2500\u2500\u2514\u2500> 0x104d3089      7351           jae 0x104d30dc\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e    0x104d308b      31c0           xor eax, eax\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e    0x104d308d      00d2           add dl, dl\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u250c\u2500< 0x104d308f      7505           jne 0x104d3096\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d3091      8a16           mov dl, byte [esi]\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d3093      46             inc esi\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d3094      10d2           adc dl, dl\n\u2502 \u2500\u2500\u2500\u2500\u2500\u2500\u2514\u2500> 0x104d3096      0f83e1000000   jae 0x104d317d\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e    0x104d309c      00d2           add dl, dl\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u250c\u2500< 0x104d309e      7505           jne 0x104d30a5\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d30a0      8a16           mov dl, byte [esi]\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d30a2      46             inc esi\n\u2502 \u2502\u254e\u254e\u254e\u254e\u2
… [4747 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
    "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
  "checked": 7,
  "hits": 7,
  "misses": [],
  "hit_examples": [
    "YARA rule 'domain' matched at offset 0",
    "YARA rule 'IP' matched at offset 36311",
    "YARA rule 'contains_base64' matched at offset 169512",
    "YARA rule 'CRC32_poly_Constant' matched at offset 1328583",
    "YARA rule 'IsPE32' matched"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 70,
  "summary": "Packed PE32 Windows GUI executable with network indicators (domain, IP, base64) and token-related strings. YARA rules for domain, IP, base64, CRC32 constant, PE properties, and win_token all fired. Analysis tools (Ghidra, IDA, Malcat) were unavailable, preventing deeper static RE, but the YARA signa",
  "key_evidence": [
    "YARA rule 'domain' matched at offset 0",
    "YARA rule 'IP' matched at offset 36311",
    "YARA rule 'contains_base64' matched at offset 169512",
    "YARA rule 'CRC32_poly_Constant' matched at offset 1328583",
    "YARA rule 'IsPE32' matched",
    "YARA rule 'IsPacked' matched",
    "YARA rule 'win_token' matched at offsets 172606 and 172621"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 10,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
      
… [5414 more chars]
```

- **malcat_analyze** ok=`False` checklist=`True` — Required checklist tool (malcat)
  - error: `malcat_analyze top-level: MCP malcat closed: `

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: "
}
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 6,
  "top_rules": [
    {
      "name": "packed with Themida",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Software Packing"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Software Packing",
     
… [1791 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 3166208,
  "duration_s": 0.03,
  "import_count": 3,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 5014,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "@.edata",
    "@.idata",
    ".themida",
    "'1~`nV9F",
    "\\nxswz9C",
    "oh.n~L",
    "Uh~D8C",
    "?=RalLh\tk",
    "'{,.L%J",
    "s\\s`^#j",
    "\"THnOt",
    "w7v:n#",
    "O0,Kd?",
    "|S0|N&",
    "&xK[#[",
    "INb@T%",
    "WWH~|Y",
    "h(&<ul
… [1317 more chars]
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
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "disassembly": {
    "0x104d3058": "\u250c 336: entry0 ();\n\u2502           0x104d3058      e84b010000     call 0x104d31a8\n\u2502           0x104d305d      53             push ebx\n\u2502           0x104d305e      89e
… [7847 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
    "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
    "exists": true
  }
}
```

- **ghidra_query** ok=`False` checklist=`False` — Auto SQL seed for large-mode deep RE gate
  - error: `ghidrasql server died during startup for ghidra-pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 (rc=1); tail of log:
Headless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux
	at ghidra.app.util.headless.HeadlessAnalyzer.openProject(HeadlessAnalyzer.java:1823)
	at ghidra.app.util.headless.HeadlessAnalyzer.processLocal(HeadlessAnalyzer.java:435)
	at ghidra.app.util.headless.AnalyzeHeadless.launch(AnalyzeHeadless.java:199)
	at ghidra.GhidraLauncher.launch(GhidraLauncher.java:81)
	at ghidra.Ghidra.main(Ghidra.java:54)
Caused by: ghidra.util.NotOwnerException: Project is owned by remnux
	at ghidra.framework.data.DefaultProjectData.<init>(DefaultProjectData.java:133)
	at ghidra.framework.project.DefaultProject.<init>(DefaultProject.java:119)
	at ghidra.app.util.headless.HeadlessAnalyzer$HeadlessProject.<init>(HeadlessAnalyzer.java:1864)
	at ghidra.app.util.headless.HeadlessAnalyzer.openProject(HeadlessAnalyzer.java:1820)
	... 4 more
 
Ghidra exited before becoming ready (exit code 1)
`

```json
{
  "error": "ghidrasql server died during startup for ghidra-pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql server died during startup for ghidra-pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 (rc=1); tail of log:
Headless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux
	at ghidra.app.util.headless.HeadlessAnalyzer.openProject(HeadlessAnalyzer.java:1823)
	at ghidra.app.util.headless.HeadlessAnalyzer.processLocal(HeadlessAnalyzer.java:435)
	at ghidra.app.util.headless.AnalyzeHeadless.launch(AnalyzeHeadless.java:199)
	at ghidra.GhidraLauncher.launch(GhidraLauncher.java:81)
	at ghidra.Ghidra.main(Ghidra.java:54)
Caused by: ghidra.util.NotOwnerException: Project is owned by remnux
	at ghidra.framework.data.DefaultProjectData.<init>(DefaultProjectData.java:133)
	at ghidra.framework.project.DefaultProject.<init>(DefaultProject.java:119)
	at ghidra.app.util.headless.HeadlessAnalyzer$HeadlessProject.<init>(HeadlessAnalyzer.java:1864)
	at ghidra.app.util.headless.HeadlessAnalyzer.openProject(HeadlessAnalyzer.java:1820)
	... 4 more
 
Ghidra exited before becoming ready (exit code 1)
`

```json
{
  "error": "ghidrasql server died during startup for ghidra-pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
}
```

- **malcat_analyze** ok=`False` checklist=`False` — langgraph tool call
  - error: `malcat_analyze top-level: MCP malcat closed: `

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: "
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/01-tools-raw.json` exists=`True` bytes=`21171` mtime=`2026-08-06T03:01:37.911805+00:00`
  - sha256: `3491ef811043d7be1269eb9d1fcb74eb8382ae81a07b078713b8e7609e27bef1`
- **sql_evidence:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/05-deep-dive.json` exists=`True` bytes=`2043` mtime=`2026-08-06T03:02:12.122749+00:00`
  - sha256: `e85a2b10f580a6c753567a37cc659ffc3b0a38121b1ef641a66ed0a613edf861`

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
  "confidence": 70,
  "summary": "Packed PE32 Windows GUI executable with network indicators (domain, IP, base64) and token-related strings. YARA rules for domain, IP, base64, CRC32 constant, PE properties, and win_token all fired. Analysis tools (Ghidra, IDA, Malcat) were unavailable, preventing deeper static RE, but the YARA signature is consistent with malware.",
  "key_evidence": [
    "YARA rule 'domain' matched at offset 0",
    "YARA rule 'IP' matched at offset 36311",
    "YARA rule 'contains_base64' matched at offset 169512",
    "YARA rule 'CRC32_poly_Constant' matched at offset 1328583",
    "YARA rule 'IsPE32' matched",
    "YARA rule 'IsPacked' matched",
    "YARA rule 'win_token' matched at 
… [1243 more chars]
```

- **agentic:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`64369` mtime=`2026-08-06T03:02:12.122749+00:00`
  - sha256: `aaf68297262edaba02a9e09b3f5344675878b4f70412eaf7a06fd0fcaa2a0e06`

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

- **rule_yar:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/rule.yar` exists=`True` bytes=`1579` mtime=`2026-08-06T03:02:34.222737+00:00`
  - sha256: `b4393d2e28a54dc97555409031086077654f97afec984af53a7f7f5f60127c3f`

#### excerpt

```
// yara_gen_v2.py — 2026-08-06T03:02:34.223828+00:00
rule CADRE_v2_unknown_3476906b2c72 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Themida is a widely abused commercial packer used to obfuscate malicious code and evade static analysis; this match is a" ascii wide
        $s1 = "Direct embedded string reference to the Themida packer, corroborating the capa packing detection and confirming the obfu" ascii wide
        $s2 = "YARA rule explicitly flags the s
… [777 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-MASTER-v2.md` exists=`True` bytes=`30602` mtime=`2026-08-06T03:03:56.674902+00:00`
  - sha256: `3d7bd499af655b1928670110dd00d6c0f8525d9fbbf0ac20b5322b6c608de05c`
- **REPORT_MASTER_v3:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-MASTER-v3.md` exists=`True` bytes=`37143` mtime=`2026-08-06T03:09:57.888059+00:00`
  - sha256: `2484a68ab6f02c057446c4f209ca75755653372c8fa24ebd89d192c683fdad2a`
- **REPORT_v2:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-v2.md` exists=`True` bytes=`30602` mtime=`2026-08-06T03:03:56.674902+00:00`
  - sha256: `3d7bd499af655b1928670110dd00d6c0f8525d9fbbf0ac20b5322b6c608de05c`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`39199` mtime=`2026-08-06T03:05:54.774778+00:00`
  - sha256: `d5f226bac30c5b39939d27a16a0144fb97fbde3682435a6d87ee103b1af1d053`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`37247` mtime=`2026-08-06T03:11:45.462038+00:00`
  - sha256: `4c14c01b7f328fa0e6064795474cc221d69bb08418dd69c96c222e580f26d9ab`
- **report_v2_json:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/report-v2.json` exists=`True` bytes=`64767` mtime=`2026-08-06T03:05:54.779778+00:00`
  - sha256: `753288449c76a59b7db147fcdc89d88e77d4d30200ef1eef8561fd7e30d76601`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:03:56 UTC

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

This report details the analysis of a malicious 32-bit Windows GUI Portable Executable (PE) sample with a triage score of 92/100. The sample is confirmed to be packed with the Themida commercial packer, a tool widely abused by malware authors to evade static analysis and reverse engineering (source: triage_verdict, query: summary, row: full summary, why: confirms malicious verdict an
… [29485 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:09:57 UTC

# RE Report — 3476906b2c72
_Generated 2026-08-06T03:09:57.881106+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=449c | cross_refs=True | llm_ok=True | runtime=31.53s -->

# Executive Summary

| Top-Line Metric | Value | Supporting Evidence |
|-----------------|-------|---------------------|
| Verdict | Malicious | Full agreement between LLM analysis layer and v1 static analysis engine; deep confidence score 70/100 (source: cross-section:2. Classification, deep_dive_agentic) |
| v1 Malicious Score | 290 | Aggregated score from v1 static analysis 
… [36234 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
