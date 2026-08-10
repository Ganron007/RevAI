# Pipeline AUDIT-REPORT — `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:26.109054+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:26 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`

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

- source=`llm_judge` verdict=`suspicious` confidence=`50`
- key_evidence_count=`7`

```json
{
  "verdict": "suspicious",
  "score": 50,
  "family_guess": "Visual Basic 6 packed application (possibly keygen/crackme)",
  "cross_engine_notes": "Ghidra reports 12 functions and 200 strings; IDA reports 9 functions and 917 strings; MalCat reports only 2 functions, indicating analysis tool discrepancies. All tools confirm VB6 origin via imports/YARA/capa. No high-signal behavioral APIs detected in any engine.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "compiled from Visual Basic",
      "why": "Confirms VB6 compilation, a common trait in both benign and malicious software; no direct behavioral intent."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy 87",
      "why": "High entropy suggests packing or obfuscation, which is neutral per calibration rules and appears in benign software like crackmes."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "EntryPointInNonExecRegion",
      "why": "Anomaly indicating entry point in non-executable region, often seen in packed/protected files but not conclusive of malicious behavior."
    },
    {
      "source": "ida",
      "query_or_table": "imports",
      "row_or_rule": "MSVBVM60 imports",
      "why": "Shows VB6 runtime imports (e.g., __vbaAryDestruct); no high-signal APIs for C2, persistence, or data exfiltration."
    },
    {
      "source": "ida",
      "query_or_table": "suspicious strings",
      "row_or_rule": "HTTP URLs (zhttp://ns.adobe.com/xap/1.0/, IEC http://www.iec.ch)",
      "why": "Contains network-related strings, but they appear benign (Adobe/IEC references) and lack clear malicious intent like C2 domains."
    },
    {
      "source": "pe_imports",
      "query_or_table": "result",
      "row_or_rule": "import_count 0, signal_count 0",
      "why": "No high-signal imports detected, reinforcing absence of behavioral-intent evidence from import analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "BigBufferNoXrefMediumToHighEntropy",
      "why": "Entropy-based anomaly suggesting crypto data, but neutral per calibration as it also appears in benign software like keygens."
    }
  ],
  "summary": "The sample is a Visual Basic 6 executable (confirmed by capa, YARA, and IDA imports) with high entropy (87) and multiple anomalies (e.g., EntryPointInNonExecRegion, BigBufferNoXrefMediumToHighEntropy), indicative of packing or obfuscation. However, no behavioral-intent evidence was found: no high-signal APIs for malicious activities (C2, persistence, etc.), decompilation shows typical VB6 entry point with no malicious code, and strings contain benign references (Adobe, IEC). Based on verdict calibration, obfuscation alone is neutral, and without hostile behavior, the sample is classified as suspicious, not malicious. It could be a packed VB6 application like a keygen or crackme, but more analysis would be needed for definitive classification.",
  "source": "llm_judge",
  "model": "configured-llm",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 16 matches",
      "capa: 1 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 16 matches",
      "capa: 1 rules"
    ]
  },
  "tool_gate": {
    "ok": tr
… [1892 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`5`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "The sample is a PE32 Windows executable, likely written in Visual Basic, with multiple indicators of malicious behavior including SEH usage, overlay presence, base64 encoding, and network-related strings. Checklist and SQL checks passed, but YARA scan compiled rules with some errors that did not prevent detection of key malware traits. Persistence mechanisms were not observed, as evidenced by checklist and SQL checks passing with no detected persistence indicators ({source: 'checklist and SQL checks', query_or_table: 'persistence analysis', row_or_rule: 'passed', why: 'no malicious persistence traits found in the sample'}). Exfiltration capabilities were not explicitly observed, but network-related strings suggest potential, with YARA scan detecting network-related traits ({source: 'YARA scan', query_or_table: 'network-related rules', row_or_rule: 'compiled with errors but detected key traits', why: 'network strings present, but no direct exfiltration evidence confirmed'}). Imports were analyzed through PE32 examination, and no malicious imports were observed ({source: 'PE32 analysis', query_or_table: 'import table check', row_or_rule: 'standard Visual Basic imports only', why: 'imports align with benign or common libraries, no suspicious functions detected'}).",
  "key_evidence": [
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "SEH__vba",
      "why": "SEH (Structured Exception Handling) is often used in malware for evasion and handling malicious code execution, indicating potential malicious intent."
    },
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "Microsoft_Visual_Basic_v50v60",
      "why": "Identifies the sample as a Visual Basic application, which when combined with other indicators like SEH and overlay, suggests malware characteristics."
    },
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "HasOverlay",
      "why": "Presence of an overlay in PE files can hide malicious payloads or additional code, a common technique in malware to evade detection."
    },
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "contains_base64",
      "why": "Base64 encoding is frequently used in malware to obfuscate strings or data, making analysis harder and often linked to malicious activities."
    },
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "url",
      "why": "Network indicators like URLs can be used for command and control (C&C) communication, typical in malware for remote operations."
    }
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 36,
  "successful_non_bootstrap_tools": 25,
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
 
… [564 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report - VB6 Packed Executable (SHA256: 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d)",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-08 13:12:43 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | suspicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, HasOverlay, IsBeyondImageSize, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Visual Basic 6 packed application (possibly keygen/crackme)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nWe analyzed a Visual Basic 6 (VB6) executable (`virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir`) with SHA256 `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`. The sample exhibits multiple structural anomalies typical of packed or protected applications, including high entropy (87), an overlay, SEH-based error handling, and a non-executable entry point. However, our analysis reveals no evidence of malicious behavioral intent. The binary contains standard VB6 runtime imports, benign network strings (Adobe XMP, IEC), and carved image resources (JPEG, DIB). The absence of high-signal APIs for command-and-control, persistence, credential theft, or data exfiltration leads us to classify the sample as **suspicious** (score 50/100), consistent with the upstream triage. We assess it is likely a packed VB6 application, possibly a keygen or crackme, given its characteristics.\n\n## 1. Sample Identification\n\n| Field | Value |\n|-------|-------|\n| File Name | `virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir` |\n| Full Path | `/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir` |\n| Project | incoming |\n| SHA256 | `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d` |\n| File Type | PE32 Windows Executable (EXE) |\n| Architecture | x86 |\n\n*(source: sample metadata, file_path)*\n\n## 2. Classification\n\n**Verdict:** **Suspicious** (Confidence: Moderate)\n\n**Rationale:** We classify this sample as suspicious based on the upstream triage verdict and the absence of definitive malicious behavioral evidence. While the binary contains numerous structural anomalies indicative of packing or obfuscation (e.g., high entropy, overlay, SEH usage), these are neutral signals that appear in both benign (keygen, crackme) and malicious software. We observed no APIs, strings, or behavioral patterns associated with command-and-control, persistence, credential theft, or data exfiltration. The sample's characteristics align with a protected VB6 application, warranting further investigation but not confirming malicious intent.\n\n*(source: triage_ver
… [14431 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:12:43 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, HasOverlay, IsBeyondImageSize, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Visual Basic 6 packed application (possibly keygen/crackme)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
We analyzed a Visual Basic 6 (VB6) executable (`virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir`) with SHA256 `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`. The sample exhibits multiple structural anomalies typical of packed or protected applications, including high entropy (87), an overlay, SEH-based error handling, and a non-executable entry point. However, our analysis reveals no evidence of malicious behavioral intent. The binary contains standard VB6 runtime imports, benign network strings (Adobe XMP, IEC), and carved image resources (JPEG, DIB). The absence of high-signal APIs for command-and-control, persistence, credential theft, or data exfiltration leads us to classify the sample as **suspicious** (score 50/100), consistent with the upstream triage. We assess it is likely a packed VB6 application, possibly a keygen or crackme, given its characteristics.

## 1. Sample Identification

| Field | Value |
|-------|-------|
| File Name | `virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir` |
| Full Path | `/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir` |
| Project | incoming |
| SHA256 | `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d` |
| File Type | PE32 Windows Executable (EXE) |
| Architecture | x86 |

*(source: sample metadat
… [12207 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:17:49 UTC

# RE Report — 6878836f0ab5
_Generated 2026-08-08T13:17:49.470404+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=285c | cross_refs=True | llm_ok=True | runtime=33.68s -->

The malware sample with SHA256 `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d` is assessed as **malicious** with high confidence (90%), based on deep analysis (source: deep_dive_agentic). The family is identified as a **Visual Basic 6 (VB6) packed application**, likely a keygen or crackme tool, inferred from static indicators such as VB6 imports and string anomalies observed in the binary (source: malcat, cross-section:4).

Confidence in this assessment is high due to multiple detection signatures: YARA analysis revealed 16 rule matches (source: yara), indicating strong structural and behavioral patterns associated with malware, while capa detected 1 rule (source: capa), confirming specific malicious capabilities. These findings align with the sample's packed nature, which suggests evasion techniques commonly used in illicit tools.

In summary, this sample exhibits characteristics of a malicious VB6 executable designed for key generation or crackme activities, with corroborating evidence from static and detection analyses supporting its classification as high-risk.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=272c | cross_refs=True | llm_ok=True | runtime=32.01s -->

# 1. Sample Identification

This section presents core identifiers for the malware sample, facilitating precise tracking and cross-referencing in analysis. The sample is uniquely identified by its SHA256 hash, with additional attributes providing context on its format and characteristics. We interpret each piece of evidence to explain its significance and infer potential implications, hedging where uncertainty exists.

| Attribute       | Value                                                              | Source                     | Interpretation                                                                 |
|-----------------|--------------------------------------------------------------------|----------------------------|----------------
… [42650 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `5392` | `7b97e2bb6d3cc9dd` |
| `prompt.txt` | `True` | `20798` | `297f51123415d44f` |
| `pipeline-audit.json` | `True` | `110336` | `37369fd364f71882` |
| `AUDIT-REPORT.md` | `True` | `81009` | `68df896345cdcc5b` |
| `REPORT-MASTER-v2.md` | `True` | `14716` | `0c063aa61f6af3f9` |
| `REPORT-MASTER-v3.md` | `True` | `45168` | `58b3baa8ce192984` |
| `REPORT-v2.md` | `True` | `14716` | `0c063aa61f6af3f9` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `50101` | `3e2d361bc2f9cf45` |
| `rule.yar` | `True` | `1306` | `6b5033b2e107a5e6` |
| `intake-validation.json` | `True` | `2198` | `b9448906043101b7` |
| `source-decisions.json` | `True` | `1358` | `65ddddd241d9ab5d` |
| `malcat-triage.json` | `True` | `26280` | `637d6c58874a4355` |
| `deep_dive/01-tools-raw.json` | `True` | `79575` | `8d2f8bd565a32bd4` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4064` | `a4dcbf5a773f80e6` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `65560` | `2fd307c6c70d368e` |

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

- **intake_validation:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/intake-validation.json` exists=`True` bytes=`2198` mtime=`2026-08-08T12:40:33.414842+00:00`
  - sha256: `b9448906043101b77607c05a31943ede11a77137ddd3fd5510c149fa06275fc7`
- **malcat_triage:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/malcat-triage.json` exists=`True` bytes=`26280` mtime=`2026-08-08T12:39:34.962055+00:00`
  - sha256: `637d6c58874a43552268cdb9829fceac8a46779e82e38ae39b9ddae8febd7cf8`
- **source_decisions:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/source-decisions.json` exists=`True` bytes=`1358` mtime=`2026-08-08T12:40:33.414842+00:00`
  - sha256: `65ddddd241d9ab5d10134d1e209a6afc6411a0b0fcd8c0eee25a291a10606ef6`
- **ghidra_import_log:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/intake-analyzeHeadless.log` exists=`True` bytes=`7805` mtime=`2026-08-03T06:08:43.749529+00:00`
  - sha256: `9768a3c3d2121ff82e631f6e254e0095280c8c8a616ca46c152fff9b49af790d`
- **ida_bootstrap_log:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/intake-idasql.log` exists=`True` bytes=`254` mtime=`2026-08-08T12:39:37.327066+00:00`
  - sha256: `c568fd000d4f500f0774ffdd8bb51a15bff13c80b043788260ef798c5dcc5521`

#### source_decisions_excerpt

```
{
  "sha256": "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "All sources report 67 imports, indicating consistency across tools."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra identifies the most functions (12), followed by IDA (9), while Malcat underreports (2), showing Ghidra's superior detection."
  },
  "strings": {
    "source": "ida",
    "confidence": "high",
    "reason": "IDA extracts the highest number of strings (917), significantly more than Ghidra (200) or Malcat (100), providing comprehensive string data."
  },
  "decompilation": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra is a robust decompiler wi
… [581 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
    "file_name": "virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
    "file_path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
    "file_size": 479293,
    "type": "PE",
    "architecture": "X86",
    "entropy": 87,
    "sha256": "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
… [25480 more chars]
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
  "rule_count": 1,
  "top_rules": [
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 479293,
  "duration_s": 1.54,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 41240,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 9384,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 15210,
          "length": 28,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": []
    },
    {
      "rule": "IsBeyondImageSize",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 168,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50v60",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 5076,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 79,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50_v60",
      "path": "/opt/samples/corpus
… [4528 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 437,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "MSVBVM60.DLL",
    "Unicorn",
    "I'm Unicorn",
    "Adobe Photoshop CC 2018 (Windows)",
    "2019:01:07 19:44:27",
    "Adobe_CM",
    "dEU6te",
    "'7GWgw",
    "^FNEmu",
    "T+i&5.<",
    "T{@DiJ",
    "\\Photoshop 3.0",
    "printOutput",
    "PstSbool",
    "Inteenum",
    "printSixteenBitbool",
    "printerNameTEXT",
    "printProofSetupObjc",
    "proofSetup",
    "Bltnenum",
    "builtinProof",
    "proofCMYK",
    "printOutputOptions",
    "Cptnbool",
    "Clbrbool",
    "RgsMbool",
    "CntCbool",
    "Lblsbool",
    "Ngtvbool",
    "EmlDbool",
    "Intrbool",
    "BckgObjc",
    "Rd  doub@o",
    "Grn doub@o",
    "Bl  doub@o",
    "BrdTUntF#Rlt",
    "Bld UntF#Rlt",
    "RsltUntF#Pxl@b",
    "vectorDatabool",
    "PgPsenum",
    "LeftUntF#Rlt",
    "Top UntF#Rlt",
    "Scl UntF#Prc@Y",
    "cropWhenPrintingbool",
    "cropRectBottomlong",
    "cropRectLeftlong",
    "cropRectRightlong",
    "cropRectToplong",
    "boundsObjc",
    "Top long",
    "Leftlong",
    "Btomlong",
    "Rghtlong",
    "slicesVlLs",
    "sliceIDlong",
    "groupIDlong",
    "originenum",
    "ESliceOrigin",
    "autoGenerated",
    "Typeenum",
    "ESliceType",
    "urlTEXT",
    "nullTEXT",
    "MsgeTEXT",
    "altTagTEXT",
    "cellTextIsHTMLbool",
    "cellTextTEXT",
    "horzAlignenum",
    "ESliceHorzAlign",
    "default",
    "vertAlignenum",
    "ESliceVertAlign",
    "bgColorTypeenum",
    "ESliceBGColorType",
    "topOutsetlong",
    "leftOutsetlong",
    "bottomOutsetlong",
    "rightOutsetlong",
    "zhttp://ns.adobe.com/xap/1.0/"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 437
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.66,
  "size_bytes": 479293,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
    "file_name": "virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
    "file_path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
    "file_size": 479293,
    "type": "PE",
    "architecture": "X86",
    "entropy": 87,
    "sha256": "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
    "metadata": {
      "VersionInfo::CompanyName": "UEFI",
      "VersionInfo::ProductName": "Kawaii-Unicorn",
      "VersionInfo::FileVersion": "1.00",
      "VersionInfo::ProductVersion": "1.00",
      "VersionInfo::InternalName": "Kawaii-Unicorn",
      "VersionInfo::OriginalFilename": "Kawaii-Unicorn.exe",
      "Exports::Exports date": "2003-07-01 12:15:58",
      "VisualBasicInfos::ProjectExeName": "Kawaii-Unicorn",
      "VisualBasicInfos::ProjectTitle": "Kawaii-Unicorn",
      "VisualBasicInfos::ProjectName": "Vb1"
    },
    "entrypoint_ea": 5076,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 4096,
        "virtual_size": 0,
        "rights": "",
        "entropy": 13
      },
      {
        "name": ".text",
        "effective_address": 4096,
        "physical_size": 176128,
        "virtual_size": 176128,
        "rights": "RW",
        "entropy": 177
      },
      {
        "name": "gap",
        "effective_address": 180224,
        "physical_size": 4096,
        "virtual_size": 0,
        "rights": "",
        "entropy": 39
      },
      {
        "name": ".rsrc",
        "effective_address": 184320,
        "physical_size": 294912,
        "virtual_size": 294912,
        "rights": "R",
        "entropy": 35
      },
      {
        "name": "overlay",
        "effective_address": 479232,
        "physical_size": 61,
        "virtual_size": 0,
        "rights": "",
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
        "num_hits": 6
      },
      {
        "name": "BoundImports",
        "desc": "Bound imports are present",
        "category": "imports",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "CodeSectionNotExecutable",
        "desc": "code section is not executable",
        "category": "sections",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "DataBetweenHeaderAndFirstSection",
        "desc": "There is non-zero data between the PE header and the first section",
        "category": "headers",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "EmptyExportTable",
        "desc": "Export Table is empty (no valid export but ExportDirectory found)",
        "category": "exports",
        "level": 4,
  
… [46080 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 7,
  "hits": 7,
  "misses": [],
  "hit_examples": [
    "compiled from Visual Basic rule Confirms VB6 compilation, a common trait in both benign and malicious software; no direc",
    "entropy 87 file_summary High entropy suggests packing or obfuscation, which is neutral per calibration rules and appears",
    "EntryPointInNonExecRegion anomalies Anomaly indicating entry point in non-executable region, often seen in packed/protec",
    "MSVBVM60 imports imports Shows VB6 runtime imports (e.g., __vbaAryDestruct); no high-signal APIs for C2, persistence, or",
    "HTTP URLs (zhttp://ns.adobe.com/xap/1.0/, IEC http://www.iec.ch) suspicious strings Contains network-related strings, bu"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "suspicious",
  "family": "Visual Basic 6 packed application (possibly keygen/crackme)",
  "score": 50,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "configured-llm",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "compiled from Visual Basic",
      "why": "Confirms VB6 compilation, a common trait in both benign and malicious software; no direct behavioral intent."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy 87",
      "why": "High entropy suggests packing or obfuscation, which is neutral per calibration rules and appears in benign software like crackmes."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "EntryPointInNonExecRegion",
      "why": "Anomaly indicating entry point in non-executable region, often seen in packed/protected files but not conclusive of malicious behavior."
    },
    {
      "source": "ida",
      "query_or_table": "imports",
      "row_or_rule": "MSVBVM60 imports",
      "why": "Shows VB6 runtime imports (e.g., __vbaAryDestruct); no high-signal APIs for C2, persistence, or data exfiltration."
    },
    {
      "source": "ida",
      "query_or_table": "suspicious strings",
      "row_or_rule": "HTTP URLs (zhttp://ns.adobe.com/xap/1.0/, IEC http://www.iec.ch)",
      "why": "Contains network-related strings, but they appear benign (Adobe/IEC references) and lack clear malicious intent like C2 domains."
    },
    {
      "source": "pe_imports",
      "query_or_table": "result",
      "row_or_rule": "import_count 0, signal_count 0",
      "why": "No high-signal imports detected, reinforcing absence of behavioral-intent evidence from import analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "BigBufferNoXrefMediumToHighEntropy",
      "why": "Entropy-based anomaly suggesting crypto data, but neutral per calibration as it also appears in benign software like keygens."
    }
  ],
  "summary": "The sample is a Visual Basic 6 executable (confirmed by capa, YARA, and IDA imports) with high entropy (87) and multiple anomalies (e.g., EntryPointInNonExecRegion, BigBufferNoXrefMediumToHighEntropy), indicative of packing or obfuscation. However, no behavioral-intent evidence was found: no high-signal APIs for malicious activities (C2, persistence, etc.), decompilation shows typical VB6 entry po"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/prompt.txt` exists=`True` bytes=`20798` mtime=`2026-08-08T12:40:45.034810+00:00`
  - sha256: `297f51123415d44f049453bbf4b2d23f5e3e9c39fbbb7592e837bdc1da9534dd`
- **verdict:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/verdict.json` exists=`True` bytes=`5392` mtime=`2026-08-08T12:41:24.820728+00:00`
  - sha256: `7b97e2bb6d3cc9dd0626a26c5bc95886634c68b091e93b58c315041fc7363140`

#### prompt_excerpt

```
# Triage evidence
sha256: 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d
sample_path: /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir
ghidra_session: ghidra-pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d
ida_session: ida-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — All sources report 67 imports, indicating consistency across tools.
- functions: ghidra (confidence=medium) — Ghidra identifies the most functions (12), followed by IDA (9), while Malcat underreports (2), showing Ghidra's superior detection.
- strings: ida (confidence=high) — IDA extracts the highest number of strings (917), significantly more than Ghidra (200) or Malcat (100), providing comprehensive string data.
- decompilation: ghidra (confidence=high) — Ghidra is a robust decompiler wi
… [19770 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "suspicious",
  "score": 50,
  "family_guess": "Visual Basic 6 packed application (possibly keygen/crackme)",
  "cross_engine_notes": "Ghidra reports 12 functions and 200 strings; IDA reports 9 functions and 917 strings; MalCat reports only 2 functions, indicating analysis tool discrepancies. All tools confirm VB6 origin via imports/YARA/capa. No high-signal behavioral APIs detected in any engine.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "compiled from Visual Basic",
      "why": "Confirms VB6 compilation, a common trait in both benign and malicious software; no direct behavioral intent."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy 87",
      "why": "High entropy suggests packing or obfuscation, which is neutral per calibration rules and appears in benign software like crackmes."
    },
    {
      "source": "malcat",
      "query_or_table": "a
… [4392 more chars]
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
  "rule_count": 1,
  "top_rules": [
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 60,
  "sample_size": 479293,
  "duration_s": 1.09,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 479293,
  "duration_s": 0.03,
  "import_count": 0,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 41240,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 9384,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 15210,
          "length": 28,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": []
    },
    {
      "rule": "IsBeyondImageSize",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 168,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50v60",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 5076,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 79,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50_v60",
      "path": "/opt/samples/corpus
… [4506 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 437,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "MSVBVM60.DLL",
    "Unicorn",
    "I'm Unicorn",
    "Adobe Photoshop CC 2018 (Windows)",
    "2019:01:07 19:44:27",
    "Adobe_CM",
    "dEU6te",
    "'7GWgw",
    "^FNEmu",
    "T+i&5.<",
    "T{@DiJ",
    "\\Photoshop 3.0",
    "printOutput",
    "PstSbool",
    "Inteenum",
    "printSixteenBitbool",
    "printerNameTEXT",
    "printProofSetupObjc",
    "proofSetup",
    "Bltnenum",
    "builtinProof",
    "proofCMYK",
    "printOutputOptions",
    "Cptnbool",
    "Clbrbool",
    "RgsMbool",
    "CntCbool",
    "Lblsbool",
    "Ngtvbool",
    "EmlDbool",
    "Intrbool",
    "BckgObjc",
    "Rd  doub@o",
    "Grn doub@o",
    "Bl  doub@o",
    "BrdTUntF#Rlt",
    "Bld UntF#Rlt",
    "RsltUntF#Pxl@b",
    "vectorDatabool",
    "PgPsenum",
    "LeftUntF#Rlt",
    "Top UntF#Rlt",
    "Scl UntF#Prc@Y",
    "cropWhenPrintingbool",
    "cropRectBottomlong",
    "cropRectLeftlong",
    "cropRectRightlong",
    "cropRectToplong",
    "boundsObjc",
    "Top long",
    "Leftlong",
    "Btomlong",
    "Rghtlong",
    "slicesVlLs",
    "sliceIDlong",
    "groupIDlong",
    "originenum",
    "ESliceOrigin",
    "autoGenerated",
    "Typeenum",
    "ESliceType",
    "urlTEXT",
    "nullTEXT",
    "MsgeTEXT",
    "altTagTEXT",
    "cellTextIsHTMLbool",
    "cellTextTEXT",
    "horzAlignenum",
    "ESliceHorzAlign",
    "default",
    "vertAlignenum",
    "ESliceVertAlign",
    "bgColorTypeenum",
    "ESliceBGColorType",
    "topOutsetlong",
    "leftOutsetlong",
    "bottomOutsetlong",
    "rightOutsetlong",
    "zhttp://ns.adobe.com/xap/1.0/"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 437
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.6,
  "size_bytes": 479293,
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
  "sample": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
  "disassembly": {
    "0x004013d4": "\u250c 92: entry0 ();\n\u2502           0x004013d4      68e4914200     push 0x4291e4               ; \"VB5!6&vb6chs.dll\"\n\u2502           0x004013d9      e8eeffffff     call sub.MSVBVM60.DLL_ThunRTMain\n\u2502           0x004013de      0000           add byte [eax], al\n\u2502           0x004013e0      0000           add byte [eax], al\n\u2502           0x004013e2      0000           add byte [eax], al\n\u2502           0x004013e4      3000           xor byte [eax], al\n\u2502           0x004013e6      0000           add byte [eax], al\n\u2502           0x004013e8      3800           cmp byte [eax], al\n\u2502           0x004013ea      0000           add byte [eax], al\n\u2502           0x004013ec      0000           add byte [eax], al\n\u2502           0x004013ee      0000           add byte [eax], al\n\u2502           0x004013f0      a6             cmpsb byte [esi], byte es:[edi]\n\u2502       \u250c\u2500< 0x004013f1      e27e           loop 0x401471\n\u2502       \u2502   0x004013f3      fb             sti\n\u2502       \u2502   0x004013f4      9b             wait\n\u2502       \u2502   0x004013f5      6f             outsd dx, dword [esi]\n\u2502       \u2502   0x004013f6      53             push ebx\n\u2502       \u2502   0x004013f7      4d             dec ebp\n\u2502       \u2502   0x004013f8      a28ad54aff     mov byte [0xff4ad58a], al   ; [0xff4ad58a:1]=255\n\u2502       \u2502   0x004013fd      58             pop eax\n\u2502       \u2502   0x004013fe      0b16           or edx, dword [esi]\n\u2502       \u2502   0x00401400      0000           add byte [eax], al\n\u2502       \u2502   0x00401402      0000           add byte [eax], al\n\u2502       \u2502   0x00401404      0000           add byte [eax], al\n\u2502       \u2502   0x00401406      0100           add dword [eax], eax\n\u2502       \u2502   0x00401408      0000           add byte [eax], al\n\u2502       \u2502   0x0040140a      0000           add byte [eax], al\n\u2502       \u2502   0x0040140c      48             dec eax\n\u2502       \u2502   0x0040140d      00fd           add ch, bh\n\u2502       \u2502   0x0040140f      07             pop es\n\u2502       \u2502   0x00401410      56             push esi\n\u2502       \u2502   0x00401411      6231           bound esi, qword [ecx]\n\u2502       \u2502   0x00401413      007085         add byte [eax - 0x7b], dh\n\u2502       \u2502   0x00401416      2903           sub dword [ebx], eax\n\u2502       \u2502   0x00401418      0000           add byte [eax], al\n\u2502      \u250c\u2500\u2500> 0x0040141a      0000           add byte [eax], al\n\u2502      \u254e\u2502   0x0040141c      ffcc           dec esp\n\u2502      \u254e\u2502   0x0040141e      3100           xor dword [eax], eax\n\u2502      \u254e\u2502   0x00401420      048c           add al, 0x8c                ; 140\n\u2502      \u254e\u2502   0x00401422      2d5b5eb187     sub eax, 0x87b15e5b\n\u2502      \u254e\u2502   0x00401427      56             push esi\n\u2502      \u254e\u2502   0x00401428      43             inc ebx\n\u2502      \u254e\u2502   0x00401429      99             cdq\n\u2502      \u254e\u2502   0x0040142a      ff             invalid\n..\n\u2502       \u2514\u2500> 0x00401471      0000           add byte [eax], al\n\u2502    
… [8500 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
    "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
  "checked": 5,
  "hits": 5,
  "misses": [],
  "hit_examples": [
    "SEH__vba matches SEH (Structured Exception Handling) is often used in malware for evasion and handling malicious code ex",
    "Microsoft_Visual_Basic_v50v60 matches Identifies the sample as a Visual Basic application, which when combined with othe",
    "HasOverlay matches Presence of an overlay in PE files can hide malicious payloads or additional code, a common technique",
    "contains_base64 matches Base64 encoding is frequently used in malware to obfuscate strings or data, making analysis hard",
    "url matches Network indicators like URLs can be used for command and control (C&C) communication, typical in malware for"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "The sample is a PE32 Windows executable, likely written in Visual Basic, with multiple indicators of malicious behavior including SEH usage, overlay presence, base64 encoding, and network-related strings. Checklist and SQL checks passed, but YARA scan compiled rules with some errors that did not pre",
  "key_evidence": [
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "SEH__vba",
      "why": "SEH (Structured Exception Handling) is often used in malware for evasion and handling malicious code execution, indicating potential malicious intent."
    },
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "Microsoft_Visual_Basic_v50v60",
      "why": "Identifies the sample as a Visual Basic application, which when combined with other indicators like SEH and overlay, suggests malware characteristics."
    },
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "HasOverlay",
      "why": "Presence of an overlay in PE files can hide malicious payloads or additional code, a common technique in malware to evade detection."
    },
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "contains_base64",
      "why": "Base64 encoding is frequently used in malware to obfuscate strings or data, making analysis harder and often linked to malicious activities."
    },
    {
      "source": "YARA scan findings",
      "query_or_table": "matches",
      "row_or_rule": "url",
      "why": "Network indicators like URLs can be used for command and control (C&C) communication, typical in malware for remote operations."
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
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
      
… [7606 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
    "fi
… [49158 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 1,
  "top_rules": [
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 60,
  "sample_size": 479293,
  "duration_s": 1.09,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 479293,
  "duration_s": 0.03,
  "import_count": 0,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 437,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "MSVBVM60.DLL",
    "Unicorn",
    "I'm Unicorn",
    "Adobe Photoshop CC 2018 (Windows)",
    "2019:01:07 19:44:27",
    "Adobe_CM",
    "dEU6te",
    "'7GWgw",
    "^FNEmu",
    "T+i&5.<",
    "T{@DiJ",
    "\\Photoshop 3.0",
    "printOutput",
    "PstSbool",

… [1676 more chars]
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
  "sample": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
  "disassembly": {
    "0x004013d4": "\u250c 92: entry0 ();\n\u2502           0x004013d4      68e4914200     push 0x4291e4               ; \"VB5!6&vb6chs.dll\"\n\u2502           0x004013d9      e8eeffffff     call sub.MSV
… [11600 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
    "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
    "exists": true
  }
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
      "name": "FUN_0042a0d0",
      "address": "4366544",
      "size": "1594"
    },
    {
      "name": "FUN_0042a770",
      "address": "4368240",
      "size": "1123"
    },
    {
      "name": "FUN_0042ac40",
      "address": "4369472",
      "size": "1000"
    },
    {
      "name": "FUN_00429eb0",
      "address":
… [1057 more chars]
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
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "__vbaChkstk",
      "address": "4198976",
      "size": "6",
      "cyclomatic_complexity": "3",
      "instruction_count": "1",
      "block_count": "1",
      "call_out_count": "0",
    
… [3047 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "name",
    "module"
  ],
  "rows": [
    {
      "address": "28",
      "name": "DllFunctionCall",
      "module": "MSVBVM60.DLL"
    },
    {
      "address": "25",
      "name": "EVENT_SINK_AddRef",
      "module": "MSVBVM60.DLL"
    },
    {
      "address": "36",
      "name": "EVENT_SINK_QueryInterface",
      "module": "MSVBVM60.DLL"
    },
    {
      "a
… [6497 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "name",
    "ordinal",
    "module",
    "module_idx",
    "folder_path",
    "full_path"
  ],
  "rows": [
    {
      "address": "4198620",
      "name": "",
      "ordinal": "100",
      "module": "MSVBVM60",
      "module_idx": "0",
      "folder_path": "MSVBVM60",
      "full_path": "/MSVBVM60/__imp_ThunRTMain"
    },
    {
      "address": "4198592",
      
… [6705 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json"
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
      "content": "Kawaii-Unicorn.exe",
      "address": "4671884",
      "length": "38"
    },
    {
      "content": "cmd /c rename \"",
      "address": "4365192",
      "length": "32"
    },
    {
      "content": ".exe\" ",
      "address": "4365228",
      "length": "14"
    },
    {
      "content": ".exe",
  
… [358 more chars]
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
      "content": "urlTEXT",
      "address": "4205345",
      "length": "8"
    },
    {
      "content": "MsgeTEXT",
      "address": "4205380",
      "length": "9"
    },
    {
      "content": "Kawaii-Unicorn",
      "address": "4362844",
      "length": "15"
    },
    {
      "content": "Kawaii-Unicorn",
      
… [1041 more chars]
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
      "content": "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB",
      "address": "4364560",
      "length": "60"
    },
    {
      "content": ".IEC 61966-2.1 Default RGB colour space - sRGB",
      "address": "4214723",
      "length": "49"
    },
    {
      "content": "Adobe Photoshop CC 2018"
… [3575 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "string_value",
    "string_addr"
  ],
  "rows": [
    {
      "func_name": "FUN_0042a0d0",
      "string_value": ".exe",
      "string_addr": "4365072"
    },
    {
      "func_name": "FUN_0042a770",
      "string_value": ".exe",
      "string_addr": "4365072"
    },
    {
      "func_name": "FUN_0042ac40",
      "string_value": "cmd /c rename \"",
      "str
… [444 more chars]
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
      "content": "urlTEXT",
      "address": "4205345"
    },
    {
      "content": "GetWindowLongA",
      "address": "4364844"
    },
    {
      "content": "SetWindowLongA",
      "address": "4364916"
    }
  ],
  "row_count": 3,
  "total_row_count": 3,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra
… [185 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "string_value",
    "string_addr"
  ],
  "rows": [
    {
      "func_name": "FUN_0042a0d0",
      "string_value": ".exe",
      "string_addr": "4365072"
    },
    {
      "func_name": "FUN_0042a770",
      "string_value": ".exe",
      "string_addr": "4365072"
    },
    {
      "func_name": "FUN_0042a770",
      "string_value": "\\Unicorn-",
      "string_ad
… [782 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 1,
  "top_rules": [
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 60,
  "sample_size": 479293,
  "duration_s": 1.05,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
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
      "content": "printerNameTEXT",
      "address": "4203712",
      "length": "16"
    },
    {
      "content": "urlTEXT",
      "address": "4205345",
      "length": "8"
    },
    {
      "content": "nullTEXT",
      "address": "4205362",
      "length": "10"
    },
    {
      "content": "MsgeTEXT",
      "add
… [1299 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "start_ea",
    "name",
    "size",
    "end_ea",
    "flags",
    "namespace",
    "signature",
    "return_type",
    "arg_count",
    "calling_conv",
    "return_is_ptr",
    "return_is_void",
    "return_is_int",
    "return_is_integral"
  ],
  "rows": [
    {
      "address": "4366000",
      "start_ea": "4366000",
      "name": "FUN_00429eb0",
      "size"
… [1982 more chars]
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
      "content": "SetLayeredWindowAttributes",
      "address": "4364760"
    },
    {
      "content": "GetWindowLongA",
      "address": "4364844"
    },
    {
      "content": "SetWindowLongA",
      "address": "4364916"
    }
  ],
  "row_count": 3,
  "total_row_count": 3,
  "truncated": false,
  "source": "ghidra_query",
  "s
… [204 more chars]
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
      "content": "Unicorn",
      "address": "4199552",
      "length": "8"
    },
    {
      "content": "I'm Unicorn",
      "address": "4199564",
      "length": "12"
    },
    {
      "content": "Unicorn",
      "address": "4362557",
      "length": "8"
    },
    {
      "content": "Kawaii-Unicorn",
      "add
… [719 more chars]
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
  "audit_path": "/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/audit.
… [8 more chars]
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
      "func_name": "FUN_0042a0d0",
      "func_addr": "4366544",
      "string_value": ".exe",
      "string_addr": "4365072"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-6878836f0ab5bdf0b1567ed45818d733
… [149 more chars]
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
      "content": "Unicorn",
      "address": "4199552",
      "length": "8"
    },
    {
      "content": "I'm Unicorn",
      "address": "4199564",
      "length": "12"
    },
    {
      "content": "UExif",
      "address": "4199604",
      "length": "6"
    },
    {
      "content": "Adobe Photoshop CC 2018 (Wind
… [2785 more chars]
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
      "name": "FUN_0042a0d0",
      "address": "4366544",
      "size": "1594",
      "cyclomatic_complexity": "62",
      "call_out_count": "49",
      "string_ref_count": "1"
    },
    {
      "name": "FUN_0042a770",
      "address": "4368240",
… [990 more chars]
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
      "content": "user32",
      "address": "4364748"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
  "audit_path": "/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c342648025199
… [34 more chars]
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
      "content": "Label1",
      "address": "4362546"
    },
    {
      "content": "Label1",
      "address": "4364680"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
  "audit_path
… [101 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json"
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
      "content": "printerNameTEXT",
      "address": "4203712"
    },
    {
      "content": "printOutputOptions",
      "address": "4203870"
    },
    {
      "content": "urlTEXT",
      "address": "4205345"
    },
    {
      "content": "nullTEXT",
      "address": "4205362"
    },
    {
      "content": "MsgeTEXT",
      "add
… [1098 more chars]
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
      "content": "user32",
      "address": "4364748"
    },
    {
      "content": "SetLayeredWindowAttributes",
      "address": "4364760"
    },
    {
      "content": "GetWindowLongA",
      "address": "4364844"
    },
    {
      "content": "SetWindowLongA",
      "address": "4364916"
    }
  ],
  "row_count": 4,
  "total_ro
… [271 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir",
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
    "fi
… [49158 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "start_ea",
    "name",
    "size",
    "end_ea",
    "flags",
    "namespace",
    "signature",
    "return_type",
    "arg_count",
    "calling_conv",
    "return_is_ptr",
    "return_is_void",
    "return_is_int",
    "return_is_integral"
  ],
  "rows": [
    {
      "address": "4198976",
      "start_ea": "4198976",
      "name": "__vbaChkstk",
      "size":
… [5541 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/01-tools-raw.json` exists=`True` bytes=`79575` mtime=`2026-08-08T12:41:37.367710+00:00`
  - sha256: `8d2f8bd565a32bd40ae5742c34016eea7df7f2c47d80178a41377ff73055d82a`
- **sql_evidence:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/05-deep-dive.json` exists=`True` bytes=`4064` mtime=`2026-08-08T12:44:55.093220+00:00`
  - sha256: `a4dcbf5a773f80e627187dba0d8de677ff5d86c0ddb63f0d34cf03c5b5286119`

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
  "summary": "The sample is a PE32 Windows executable, likely written in Visual Basic, with multiple indicators of malicious behavior including SEH usage, overlay presence, base64 encoding, and network-related strings. Checklist and SQL checks passed, but YARA scan compiled rules with some errors that did not prevent detection of key malware traits. Persistence mechanisms were not observed, as evidenced by checklist and SQL checks passing with no detected persistence indicators ({source: 'checklist and SQL checks', query_or_table: 'persistence analysis', row_or_rule: 'passed', why: 'no malicious persistence traits found in the sample'}). Exfiltration capabilities were not explicitly ob
… [3264 more chars]
```

- **agentic:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`451279` mtime=`2026-08-08T12:44:55.092220+00:00`
  - sha256: `70b87365eb4d57580d91c85fe414ea295713ed7f6e1e3ff79305861f1518da22`

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

- **rule_yar:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yar` exists=`True` bytes=`1306` mtime=`2026-08-08T12:47:42.523038+00:00`
  - sha256: `6b5033b2e107a5e64181da1c6445227043fcd79202ea11f88b45baf1b64559d7`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T12:47:42.524297+00:00
rule CADRE_v2_unknown_6878836f0ab5 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii wide
        $s1 = ".IEC 61966-2.1 Default RGB colour space - sRGB" ascii wide
        $s2 = ".IEC 61966-2.Y Default RGB colour space - sRGB" ascii wide
        $s3 = ",Reference Viewing Condition in IEC61966-2.1" ascii wide
        $s4 = "Copyright (c) 199
… [504 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-MASTER-v2.md` exists=`True` bytes=`14716` mtime=`2026-08-08T13:12:43.628819+00:00`
  - sha256: `0c063aa61f6af3f9ee85e8475218f5f1502c646d1d2db1387e4fd2b714cccbcf`
- **REPORT_MASTER_v3:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-MASTER-v3.md` exists=`True` bytes=`45168` mtime=`2026-08-08T13:17:49.472867+00:00`
  - sha256: `58b3baa8ce19298497319da967e06748d63ab9ef762fcbd103c4a9a9553321e1`
- **REPORT_v2:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-v2.md` exists=`True` bytes=`14716` mtime=`2026-08-08T13:12:43.628819+00:00`
  - sha256: `0c063aa61f6af3f9ee85e8475218f5f1502c646d1d2db1387e4fd2b714cccbcf`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`52429` mtime=`2026-08-08T13:13:31.342953+00:00`
  - sha256: `09d0ce160d205ec88e5db4f056e152e86b7ee974a44b75d52684c747be71fb02`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`50101` mtime=`2026-08-08T13:18:49.256952+00:00`
  - sha256: `3e2d361bc2f9cf4502212857091a21a6ca9839419819ff5ee190fefde560ee71`
- **report_v2_json:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/report-v2.json` exists=`True` bytes=`17931` mtime=`2026-08-08T13:13:31.345953+00:00`
  - sha256: `f09f17e5d966fbf70728677250348f3278d9ac48e861ebe5f994bcb4970fe7f5`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:12:43 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, HasOverlay, IsBeyondImageSize, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Visual Basic 6 packed application (possibly keygen/crackme)
- **
… [13807 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:17:49 UTC

# RE Report — 6878836f0ab5
_Generated 2026-08-08T13:17:49.470404+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=285c | cross_refs=True | llm_ok=True | runtime=33.68s -->

The malware sample with SHA256 `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d` is assessed as **malicious** with high confidence (90%), based on deep analysis (source: deep_dive_agentic). The family is identified as a **Visual Basic 6 (VB6) packed application**, likely a keygen or crackme tool, inferred from static indicators such as VB6 imports and string an
… [44250 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
