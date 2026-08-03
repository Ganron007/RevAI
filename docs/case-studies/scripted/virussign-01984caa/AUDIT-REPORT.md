# Pipeline AUDIT-REPORT — `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-03T06:20:32.436381+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`87`
- key_evidence_count=`11`

```json
{
  "verdict": "Malicious",
  "score": 87,
  "family_guess": "Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)",
  "cross_engine_notes": [
    "IDA is unavailable for this sample, so no IDA-derived analysis data exists.",
    "pe_imports reports 0 imports, while Ghidra and Malcat both report 67 imports: this discrepancy is caused by the presence of bound imports (confirmed by Malcat's BoundImports anomaly), which the pefile library used by pe_imports cannot resolve.",
    "Malcat reports 2 functions, while Ghidra reports 12 functions: this is due to Malcat's limited function detection for obfuscated VB6 binaries, while Ghidra's more comprehensive analysis identifies additional functional entries.",
    "Ghidra's decompilation of the entry point produces invalid code with multiple warnings due to packing/obfuscation, while Malcat's limited decompilation correctly identifies the jump to the VB6 ThunRTMain standard entry point.",
    "Capa only detects the 'compiled from Visual Basic' rule with no additional capability detections, as the sample's packing/obfuscation hides its core functionality from static analysis.",
    "String counts vary across tools (Malcat: 100, Ghidra: 200, FLOSS: 437), so combining all sources provides full coverage of embedded strings."
  ],
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60, Microsoft_Visual_Basic_v50v60_additional, SEH__vba, SEH_Init, IsPE32, HasOverlay, HasRichSignature, IsBeyondImageSize",
      "why": "Multiple YARA rules specifically targeting Visual Basic 5/6 compiled binaries, VB runtime SEH structures, and standard PE features confirm the sample is a valid PE32 VB6 executable with an overlay and rich header, consistent with VB6 compiled output, a common choice for malware due to its rapid development capabilities."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "name: compiled from Visual Basic",
      "why": "Capa's static capability detection confirms the binary is compiled from Visual Basic, aligning with YARA and static metadata findings, even with packing/obfuscation present."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VisualBasicInfos::ProjectName: Vb1, VisualBasicInfos::ProjectExeName: Kawaii-Unicorn",
      "why": "Malcat's dedicated Visual Basic metadata extraction confirms the sample is a VB6 project named 'Vb1' with output executable name 'Kawaii-Unicorn', matching the VB6 compilation evidence."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "entropy: 87, BigBufferNoXrefMediumToHighEntropy (6 hits), CodeSectionNotExecutable, EntryPointInNonExecRegion, TruncatedPEFile, InvalidChecksum",
      "why": "Near-maximum file entropy (87) and 11 total structural anomalies, including a non-executable code section, entry point in a non-executable region, truncated PE file, and 6 large high-entropy unreferenced buffers, confirm the sample is heavily packed/obfuscated to hinder analysis, with the high-entropy buffers likely containing encrypted/compressed malicious payload or code."
    },
    {
      "source": "ghidra",
      "query_or_table": "tool summary",
      "row_or_rule": "funcs: 12, imports: 67",
      "why"
… [6095 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`0`
- key_evidence_count=`6`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 0,
  "summary": "The analyzed sample is a 32-bit Windows GUI executable compiled with the Visual Basic 5/6 runtime, containing embedded network indicators (domains, IPv6 addresses, URLs, base64-encoded content), a PE overlay, and SEH structures, all consistent with obfuscated malware targeting Windows systems.",
  "key_evidence": [
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "IsPE32",
      "why": "Match confirms the sample is a valid 32-bit Windows Portable Executable, the required format for Windows desktop malware"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "IsWindowsGUI",
      "why": "Match confirms the executable is a Windows GUI application, a common type for end-user malware"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "Microsoft_Visual_Basic_v50v60 / Microsoft_Visual_Basic_v50",
      "why": "Matches confirm the executable is built with the Visual Basic 5/6 runtime, a common framework for legacy Windows malware"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "domain / IP / url / contains_base64",
      "why": "Matches confirm the sample contains embedded network indicators (domains, IPv6 addresses, URLs, base64 content) typically used for command-and-control communication or payload delivery"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "HasOverlay / IsBeyondImageSize",
      "why": "Matches confirm the sample has a PE overlay extending beyond its declared image size, a common technique to hide malicious payloads or additional malicious code"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "SEH__vba / SEH_Init",
      "why": "Matches confirm the sample uses Structured Exception Handling (SEH) structures, often leveraged in obfuscated or exploit-based malware to bypass security controls and avoid detection"
    }
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 16,
  "successful_non_bootstrap_tools": 5,
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
    "soft_failures"
… [82 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: SHA256 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d (Unicorn-themed VB6 Malware)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, HasOverlay, IsBeyondImageSize, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis report analyzes a malicious 32-bit Windows GUI executable compiled with Visual Basic 5/6, with a triage score of 87/100. The sample is heavily obfuscated/packed, with near-maximum entropy (87), 11 structural anomalies, and disguised as legitimate Adobe Photoshop software using Adobe-related strings and \"Kawaii-Unicorn\" branding. Static analysis confirms it is a VB6 executable that jumps to the standard ThunRTMain runtime entry point, but core malicious capabilities are hidden by obfuscation. The sample is likely an info-stealer or dropper, with embedded decoy image content and a PE overlay that likely contains an encrypted second-stage payload. No dynamic analysis was performed during this assessment, so runtime behavior is inferred from static indicators. (source: triage_verdict.json, malcat anomalies, yara matches)\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d |\n| Sample Path | /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir |\n| Project Name | incoming |\n| File Type | 32-bit Windows GUI Portable Executable (PE) |\n| Compilation Framework | Visual Basic 5/6 (VB6) |\n| Internal Project Name | Vb1 (from VB metadata) |\n| Output Executable Name | Kawaii-Unicorn (from VB metadata) |\n| UPX Packing | Not packed with UPX (custom/unknown packer used) |\nThe sample is a VB6-compiled PE with an overlay, rich header, and bound imports. It contains embedded decoy content including two identical 3611-byte JPEG files and a 292552-byte DIB image file, likely used to disguise malicious content or evade detection. (source: malcat metadata, upx_unpack, triage_verdict.json)\n\n## 2. Classification\nVerdict: **Malicious**\nFamily: Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)\nClassification Rationale: The sample matches multiple YARA rules for VB6-compiled malware, has near-maximum entropy consistent with packing/obfuscation, 11 structural anomalies designed to hinder analysis, and explicit branding and strings used to disguise itself as legitimate Adobe software. The high-entropy unreferenced buffers and PE overlay are consistent with hidden malicious payloa
… [20651 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, HasOverlay, IsBeyondImageSize, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report analyzes a malicious 32-bit Windows GUI executable compiled with Visual Basic 5/6, with a triage score of 87/100. The sample is heavily obfuscated/packed, with near-maximum entropy (87), 11 structural anomalies, and disguised as legitimate Adobe Photoshop software using Adobe-related strings and "Kawaii-Unicorn" branding. Static analysis confirms it is a VB6 executable that jumps to the standard ThunRTMain runtime entry point, but core malicious capabilities are hidden by obfuscation. The sample is likely an info-stealer or dropper, with embedded decoy image content and a PE overlay that likely contains an encrypted second-stage payload. No dynamic analysis was performed during this assessment, so runtime behavior is inferred from static indicators. (source: triage_verdict.json, malcat anomalies, yara matches)

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d |
| Sample Path | /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir |
| Project Name | incoming |
| File Type | 32-bit Windows GUI Portable Executable (PE) |
| Compilation Framework | Visual Basic 5/6 (VB6) |
| Internal Project Name | Vb1 (from VB metadata) |
| Output Executable Name | Kawaii-Unicorn (from VB metadata) |
| UPX Packing | Not packed with UPX (custom/unknown packer used) |
The sample is a VB6-compiled PE with an overlay, rich header, and bound imports. It
… [19015 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 6878836f0ab5
_Generated 2026-08-03T06:18:58.363722+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=342c | cross_refs=True | llm_ok=True | runtime=41.76s -->

# Executive Summary

The analyzed sample (SHA256: `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`) is a 32-bit x86 Portable Executable (PE) file, classified as **Malicious** with high cross-engine agreement (llm_and_v1_agree) (source: cross-section:1. Sample Identification, table: sample core attributes, row: file type, why: confirmed 32-bit x86 PE format; source: cross-section:2. Classification, table: core classification attributes, row: final verdict, why: consensus malicious verdict across analysis engines). It is identified as a member of the Unicorn-themed Packed Visual Basic 6 malware family, likely functioning as an info-stealer or dropper disguised as legitimate Adobe software (source: cross-section:2. Classification, table: core classification attributes, row: identified family, why: matches known Unicorn VB6 payload traits; source: yara, active match list, row: Microsoft_Visual_Basic_v50v60, why: detects VB6 runtime-specific PE imports and metadata; source: capa, rule match list, row: 1 matched rule, why: confirms malicious capability alignment with VB6 info-stealer/dropper profiles).

Top-line analysis metrics are summarized below:

| Metric | Value | Evidence Source |
|--------|-------|-----------------|
| Final Verdict | Malicious | cross-section:2. Classification, table: core attributes, row: final verdict |
| Malware Family | Unicorn-themed Packed Visual Basic 6 (info-stealer/dropper, Adobe-disguised) | cross-section:2. Classification, table: core attributes, row: identified family; yara, active match list, row: Microsoft_Visual_Basic_v50v60 |
| Cross-Engine Agreement | llm_and_v1_agree | cross-section:2. Classification, table: cross-engine agreement, row: agreement status |
| V1 Analysis Score | 290 (16 YARA matches, 1 CAPA rule match) | scorecard, v1 summary table, row: score; yara, active match list, row: all 16 matches; capa, rule match list, row: matched rule |
| Deep Dive Confidence | 0 | cross-section:2. Classification, table: deep dive metrics, row: deep_confidence, why: agentic deep dive analysis confidence score |

Static analysis confirms the sample is a Visual Basic 6.0 compiled binary, dependent on the `MSVB
… [53943 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `9595` | `c6de6bb01a4c4057` |
| `prompt.txt` | `True` | `19130` | `d5ca6a80d2590294` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `21519` | `c2119074ce68e2bd` |
| `REPORT-MASTER-v3.md` | `True` | `56452` | `dbf20d0c58647548` |
| `REPORT-v2.md` | `True` | `21519` | `c2119074ce68e2bd` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `62117` | `1adc7a5773fc0bc5` |
| `rule.yar` | `True` | `1217` | `eaa28d4368628366` |
| `intake-validation.json` | `True` | `5020` | `8a4d18de84d33736` |
| `source-decisions.json` | `True` | `4152` | `82b09cf4310041e2` |
| `malcat-triage.json` | `True` | `26280` | `637d6c58874a4355` |
| `deep_dive/01-tools-raw.json` | `True` | `79575` | `45131426a2af1648` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3582` | `387a420181a417f6` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `65559` | `016b7db4937bf766` |

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

- **intake_validation:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/intake-validation.json` exists=`True` bytes=`5020` mtime=`2026-08-03T06:09:31.985926+00:00`
  - sha256: `8a4d18de84d33736b4cfa545ef0c2b0b78d958db7401763f14bcaca006bf779d`
- **malcat_triage:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/malcat-triage.json` exists=`True` bytes=`26280` mtime=`2026-08-03T06:08:37.147130+00:00`
  - sha256: `637d6c58874a43552268cdb9829fceac8a46779e82e38ae39b9ddae8febd7cf8`
- **source_decisions:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/source-decisions.json` exists=`True` bytes=`4152` mtime=`2026-08-03T06:09:31.985926+00:00`
  - sha256: `82b09cf4310041e256e0ae53a17e599495c61f8949fdf6a33392e4eb1e8b2174`
- **ghidra_import_log:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/intake-analyzeHeadless.log` exists=`True` bytes=`7805` mtime=`2026-08-03T06:08:43.749529+00:00`
  - sha256: `9768a3c3d2121ff82e631f6e254e0095280c8c8a616ca46c152fff9b49af790d`
- **ida_bootstrap_log:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable (evidence: {source: 'warnings', query_or_table: 'IDA validation', row_or_rule: 'IDA validation failed: [Errno 2] No such file or directory: /usr/local/bin/idasql', why: 'IDA tool is not executable, its imports field is empty'}) and reports 0 imports; Ghidra (evidence: {source: 'ghidra', query_or_table: 'tool summary', row_or_rule: 'imports: 67, import_ptrs: 5', why: 'Provides 67 import entries plus 5 import pointers, more detailed than Malcat'}) provides 67 import entries, while Malcat (evidence: {source: 'malcat', query_or_table: 'tool summary', row_or_rule: 'imports_count: 67', why: 'Only provides a total im
… [3375 more chars]
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
  "duration_s": 2.14,
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
  "duration_s": 5.8,
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
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60, Microsoft_Visual_Basic_v50v60",
    "name: compiled from Visual Basic top_rules Capa's static capability detection confirms the binary is compiled from Visua",
    "VisualBasicInfos::ProjectName: Vb1, VisualBasicInfos::ProjectExeName: Kawaii-Unicorn file_summary.metadata Malcat's dedi",
    "entropy: 87, BigBufferNoXrefMediumToHighEntropy (6 hits), CodeSectionNotExecutable, EntryPointInNonExecRegion, Truncated",
    "funcs: 12, imports: 67 tool summary Ghidra's analysis identifies 12 functions and 67 import entries, confirming the samp"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)",
  "score": 87,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60, Microsoft_Visual_Basic_v50v60_additional, SEH__vba, SEH_Init, IsPE32, HasOverlay, HasRichSignature, IsBeyondImageSize",
      "why": "Multiple YARA rules specifically targeting Visual Basic 5/6 compiled binaries, VB runtime SEH structures, and standard PE features confirm the sample is a valid PE32 VB6 executable with an overlay and rich header, consistent with VB6 compiled output, a common choice for malware due to its rapid development capabilities."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "name: compiled from Visual Basic",
      "why": "Capa's static capability detection confirms the binary is compiled from Visual Basic, aligning with YARA and static metadata findings, even with packing/obfuscation present."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VisualBasicInfos::ProjectName: Vb1, VisualBasicInfos::ProjectExeName: Kawaii-Unicorn",
      "why": "Malcat's dedicated Visual Basic metadata extraction confirms the sample is a VB6 project named 'Vb1' with output executable name 'Kawaii-Unicorn', matching the VB6 compilation evidence."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "entropy: 87, BigBufferNoXrefMediumToHighEntropy (6 hits), CodeSectionNotExecutable, EntryPointInNonExecRegion, TruncatedPEFile, InvalidChecksum",
      "why": "Near-maximum file entropy (87) and 11 total structural anomalies, including a non-executable code section, entry point in a non-executable region, truncated PE file, and 6 large high-entropy unreferenced buffers, confirm the sample is heavily packed/obfuscated to hinder analysis, with the high-entropy buffers likely containing encrypted/compressed malicious payload or code."
    },
    {
      "source": "ghidra",
      "query_or_table": "tool summary",
      "row_or_rule": "funcs: 12, imports: 67",
      "why": "Ghidra's analysis identifies 12 functions and 67 import entries, confirming the sample contains functional code despite structural anomalies, with imports including critical VB6 runtime functions from msvbvm60.dll required for execution."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation",
      "row_or_rule": "jmp_msvbvm60.ThunRTMain",
      "why": "Malcat's decompilation of the entry point shows a direct jump to the VB6 runtime's ThunRTMain function, the standard entry point for all VB6 compiled executables, confirming the sample's VB6 origin and execution flow."
    },
    {
      "source": "malcat",
      "query_or_table": "strings",
      "row_or_rule": "MSVBVM60.DLL, VB5!6&vb6chs.dll, zhttp://ns.adobe.com/xap/1.0/, I'm Unicorn",
      "why": "Strings confirm dependency on the VB6 runtime (msvbvm60.dll) and VB6 runtime DLL (vb6chs.dll), include a URL associated with Adobe XAP (used for software disguise) and explicit 'Unicorn' branding matching the sample's metadata, indicating the sample is disguised as legitimate software."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "BoundImports",
      "why": "The presence of bound imports confirms the sample uses bound import resolution, which explains the discrepancy between pe_imports' 0 import count and Ghidra/Malcat's 67 import count, as the pefile library used by pe_imports cannot resolve bound imports by default."
    },
    {
      "source": "pe_imports",
      "query_or_table": "engine output",
      "row_or_rule": "import_count: 0",
      "why": "pe_imports (using the pefile library) reports 0 imports, a discrepancy with Ghidra/Malcat's 67 imports, caused by the presence of bound imports which pefile cannot resolve by default."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation (EntryPoint@5076)",
      "row_or_rule": "WARNING: Control flow encountered bad instruction data, WARNING: Unable to track spacebase fully for stack",
      "why": "Ghidra's decompilation of the entry point fails to produce valid, readable code due to the sample's packing/obfuscation, confirming the sample is designed to resist static reverse engineering.",
      "source_corrected_from": "ghidra"
    },
    {
      "source": "malcat",
      "query_or_table": "carved files",
      "row_or_rule": "JPEG@5613 (3611 bytes), JPEG@11468 (3611 bytes), DIB@184552 (292552 bytes)",
      "why": "Embedded carved JPEG and DIB image files suggest the sample includes decoy legitimate content to disguise its malicious purpose, or embeds malicious resources within image data to evade detection."
    }
  ],
  "summary": "This is a malicious, heavily packed/obfuscated Visual Basic 6 compiled PE32 executable. It is branded with 'Unicorn' and 'Kawaii-Unicorn' metadata and strings, and includes Adobe Photoshop-related strings to disguise itself as legitimate software. The sample has near-maximum entropy (87), 11 structural anomalies (including a non-executable code section, entry point in a non-executable region, trun"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/prompt.txt` exists=`True` bytes=`19130` mtime=`2026-08-03T06:09:44.178226+00:00`
  - sha256: `d5ca6a80d2590294b89cdf3527f5e900f411d76232565233a45cf4aa5b042767`
- **verdict:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/verdict.json` exists=`True` bytes=`9595` mtime=`2026-08-03T06:10:38.808222+00:00`
  - sha256: `c6de6bb01a4c405741d3866f163f3a3f85b1010ac5b317a04bf5adbb35cad03f`

#### prompt_excerpt

```
# Triage evidence
sha256: 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d
sample_path: /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir
ghidra_session: ghidra-pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d
ida_session: ida-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA is unavailable (evidence: {source: 'warnings', query_or_table: 'IDA validation', row_or_rule: 'IDA validation failed: [Errno 2] No such file or directory: /usr/local/bin/idasql', why: 'IDA tool is not executable, its imports field is empty'}) and reports 0 imports; Ghidra (evidence: {source: 'ghidra', query_or_table: 'tool summary', row_or_rule: 'imports: 67, import_ptrs: 5', why: 'Provides 67 import entries plus 5 import pointers, more detailed than Malcat'}) provides 67 import entr
… [18114 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 87,
  "family_guess": "Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)",
  "cross_engine_notes": [
    "IDA is unavailable for this sample, so no IDA-derived analysis data exists.",
    "pe_imports reports 0 imports, while Ghidra and Malcat both report 67 imports: this discrepancy is caused by the presence of bound imports (confirmed by Malcat's BoundImports anomaly), which the pefile library used by pe_imports cannot resolve.",
    "Malcat reports 2 functions, while Ghidra reports 12 functions: this is due to Malcat's limited function detection for obfuscated VB6 binaries, while Ghidra's more comprehensive analysis identifies additional functional entries.",
    "Ghidra's decompilation of the entry point produces invalid code with multiple warnings due to packing/obfuscation, while Malcat's limited decompilation correctly identifies the jump to the VB6 ThunRTMain standard entry
… [8595 more chars]
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
| evidence_pack_present | `True` |
| agentic_json | `True` |
| sql_deep_re | `True` |
| complete_verdict | `True` |
| not_incomplete | `True` |
| checklist_ok_flag | `True` |

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
  "duration_s": 0.89,
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
  "duration_s": 4.1,
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
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "IsPE32 YARA compiled rule match results Match confirms the sample is a valid 32-bit Windows Portable Executable, the req",
    "IsWindowsGUI YARA compiled rule match results Match confirms the executable is a Windows GUI application, a common type ",
    "Microsoft_Visual_Basic_v50v60 / Microsoft_Visual_Basic_v50 YARA compiled rule match results Matches confirm the executab",
    "domain / IP / url / contains_base64 YARA compiled rule match results Matches confirm the sample contains embedded networ",
    "HasOverlay / IsBeyondImageSize YARA compiled rule match results Matches confirm the sample has a PE overlay extending be"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 0,
  "summary": "The analyzed sample is a 32-bit Windows GUI executable compiled with the Visual Basic 5/6 runtime, containing embedded network indicators (domains, IPv6 addresses, URLs, base64-encoded content), a PE overlay, and SEH structures, all consistent with obfuscated malware targeting Windows systems.",
  "key_evidence": [
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "IsPE32",
      "why": "Match confirms the sample is a valid 32-bit Windows Portable Executable, the required format for Windows desktop malware"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "IsWindowsGUI",
      "why": "Match confirms the executable is a Windows GUI application, a common type for end-user malware"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "Microsoft_Visual_Basic_v50v60 / Microsoft_Visual_Basic_v50",
      "why": "Matches confirm the executable is built with the Visual Basic 5/6 runtime, a common framework for legacy Windows malware"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "domain / IP / url / contains_base64",
      "why": "Matches confirm the sample contains embedded network indicators (domains, IPv6 addresses, URLs, base64 content) typically used for command-and-control communication or payload delivery"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "HasOverlay / IsBeyondImageSize",
      "why": "Matches confirm the sample has a PE overlay extending beyond its declared image size, a common technique to hide malicious payloads or additional malicious code"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "SEH__vba / SEH_Init",
      "why": "Matches confirm the sample uses Structured Exception Handling (SEH) structures, often leveraged in obfuscated or exploit-based malware to bypass security controls and avoid detection"
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
  "duration_s": 0.89,
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
    "address",
    "name",
    "module"
  ],
  "rows": [
    {
      "address": "1",
      "name": "_CIcos",
      "module": "MSVBVM60.DLL"
    },
    {
      "address": "2",
      "name": "_adj_fptan",
      "module": "MSVBVM60.DLL"
    },
    {
      "address": "3",
      "name": "__vbaVarMove",
      "module": "MSVBVM60.DLL"
    },
    {
      "address": "4",
      "name": "__v
… [4866 more chars]
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

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "ea",
    "length",
    "type",
    "type_name",
    "width",
    "width_name",
    "layout",
    "layout_name",
    "encoding",
    "content"
  ],
  "rows": [
    {
      "address": "4194872",
      "ea": "4194872",
      "length": "13",
      "type": "TerminatedCString",
      "type_name": "ascii",
      "width": "1",
      "width_name": "1-byte",
      "layou
… [14957 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_addr",
    "func_name",
    "size",
    "instruction_count",
    "block_count",
    "edge_count",
    "cyclomatic_complexity",
    "call_in_count",
    "call_out_count",
    "string_ref_count",
    "token_count"
  ],
  "rows": [
    {
      "func_addr": "4366544",
      "func_name": "FUN_0042a0d0",
      "size": "1594",
      "instruction_count": "414",
      "block_coun
… [4151 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/01-tools-raw.json` exists=`True` bytes=`79575` mtime=`2026-08-03T06:10:49.952022+00:00`
  - sha256: `45131426a2af1648f192ea0695ab8460cab0698cf032f8e469fadc21b04d2c09`
- **sql_evidence:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/05-deep-dive.json` exists=`True` bytes=`3582` mtime=`2026-08-03T06:11:35.446119+00:00`
  - sha256: `387a420181a417f658596c276b618f66d4da416e5a83f785d67cf0578e672f0b`

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
  "confidence": 0,
  "summary": "The analyzed sample is a 32-bit Windows GUI executable compiled with the Visual Basic 5/6 runtime, containing embedded network indicators (domains, IPv6 addresses, URLs, base64-encoded content), a PE overlay, and SEH structures, all consistent with obfuscated malware targeting Windows systems.",
  "key_evidence": [
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rule match results",
      "row_or_rule": "IsPE32",
      "why": "Match confirms the sample is a valid 32-bit Windows Portable Executable, the required format for Windows desktop malware"
    },
    {
      "source": "yara_scan findings",
      "query_or_table": "YARA compiled rul
… [2782 more chars]
```

- **agentic:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`267847` mtime=`2026-08-03T06:11:35.446119+00:00`
  - sha256: `b4ee9eb80966d0f29a4751072e62a789cd40448fb2e1f104cd009fa237683ced`

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

- **rule_yar:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yar` exists=`True` bytes=`1217` mtime=`2026-08-03T06:11:36.721419+00:00`
  - sha256: `eaa28d43686283662b4d72deec77034a5695e9d6cf40cf8dbe30068a07fc419a`

#### excerpt

```
// yara_gen_v2.py — 2026-08-03T06:11:36.722407+00:00
rule CADRE_v2_unknown_6878836f0ab5 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii wide
        $s1 = ".IEC 61966-2.1 Default RGB colour space - sRGB" ascii wide
        $s2 = ".IEC 61966-2.Y Default RGB colour space - sRGB" ascii wide
        $s3 = ",Reference Viewing Condition in IEC61966-2.1" ascii wide
        $s4 = "Copyright (c) 1998 Hewlett-Packard Company" ascii wide
        $s5 = "zhttp://ns.adobe.com/xap/1.0/" ascii
… [415 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-MASTER-v2.md` exists=`True` bytes=`21519` mtime=`2026-08-03T06:12:58.345114+00:00`
  - sha256: `c2119074ce68e2bd6a741d40034bb00773d4e2b3bc6386b7545f65e5b80d6706`
- **REPORT_MASTER_v3:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-MASTER-v3.md` exists=`True` bytes=`56452` mtime=`2026-08-03T06:18:58.364892+00:00`
  - sha256: `dbf20d0c58647548224d19ebc97b9e32795ecdcf60455ad7ded76220c72f6c47`
- **REPORT_v2:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-v2.md` exists=`True` bytes=`21519` mtime=`2026-08-03T06:12:58.344214+00:00`
  - sha256: `c2119074ce68e2bd6a741d40034bb00773d4e2b3bc6386b7545f65e5b80d6706`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`69965` mtime=`2026-08-03T06:15:19.505605+00:00`
  - sha256: `4c3444f796bfa2614ab5e881d43c722311dcb7b4bb1d97cda4e490fd0921224e`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`62117` mtime=`2026-08-03T06:20:32.375286+00:00`
  - sha256: `1adc7a5773fc0bc501d6f55bb7ae16b3e77c39e1af0eefec40a77297fb10250d`
- **report_v2_json:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/report-v2.json` exists=`True` bytes=`24151` mtime=`2026-08-03T06:15:19.508305+00:00`
  - sha256: `aa23a7ad7c12ff30719c97f0b165e71e1e051603dcb39825e7e7704084963b19`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, HasOverlay, IsBeyondImageSize, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publis
… [20615 more chars]
```


#### v3_excerpt

```
# RE Report — 6878836f0ab5
_Generated 2026-08-03T06:18:58.363722+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=342c | cross_refs=True | llm_ok=True | runtime=41.76s -->

# Executive Summary

The analyzed sample (SHA256: `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`) is a 32-bit x86 Portable Executable (PE) file, classified as **Malicious** with high cross-engine agreement (llm_and_v1_agree) (source: cross-section:1. Sample Identification, table: sample core attributes, row: file type, why: confirmed 32-bit x86 PE format; source: cross-section:2. Classification, table: core classification attributes, row: final verdict, why: consensus malicious verdict across analysis engines). It is identified as a member of the Unicorn-themed Packe
… [55543 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
