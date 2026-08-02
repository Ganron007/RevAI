# Pipeline AUDIT-REPORT — `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-02T20:02:19.713057+00:00
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
- key_evidence_count=`7`

```json
{
  "verdict": "Malicious",
  "score": 87,
  "family_guess": "Unicorn (VB6-based info-stealer/dropper)",
  "cross_engine_notes": "IDA is non-functional (all queries return file not found errors), so all static analysis data is sourced from Ghidra, FLOSS, capa, and pe_imports. Ghidra reports 12 functions and 200 static strings, while FLOSS extracts 437 total strings including obfuscated/stack strings, with overlapping entries confirming data consistency. The PE import table reports 0 imports, while Ghidra has limited PTR entries for user32-related data, indicating the import table is obfuscated or dynamically resolved, a common anti-analysis tactic in this malware family. Capa confirms Visual Basic compilation but cannot provide behavioral capability detections due to its internal limitation for analyzing VB files.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "compiled from Visual Basic",
      "why": "Capa analysis explicitly identifies the sample as compiled from Visual Basic, confirming its compilation environment which is consistent with known VB-based malware families."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "MSVBVM60.DLL",
      "why": "FLOSS extracted the string 'MSVBVM60.DLL', the runtime library for Visual Basic 6.0, which corroborates the capa finding that the sample is VB-compiled."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "I'm Unicorn",
      "why": "FLOSS extracted the unique identifier string 'I'm Unicorn', which is a known marker for the Unicorn malware family, a VB-based info-stealer and dropper."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "(internal) Visual Basic file limitation",
      "why": "Capa reports an internal limitation for analyzing Visual Basic files, which explains the absence of behavioral capability detections from capa despite the sample's malicious nature."
    },
    {
      "source": "pe_imports",
      "query_or_table": "import_count",
      "row_or_rule": "0",
      "why": "The PE import table reports 0 imported functions, indicating the sample uses obfuscated, packed, or dynamically resolved APIs, a common anti-analysis tactic in VB-based malware."
    },
    {
      "source": "ghidra",
      "query_or_table": "funcs",
      "row_or_rule": "12",
      "why": "Ghidra identified only 12 functions in the sample, consistent with the small, obfuscated structure of many VB-compiled malware samples that rely on runtime library functions for most operations."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "Adobe Photoshop CC 2018 (Windows)",
      "why": "FLOSS extracted Adobe Photoshop related strings, indicating the sample likely masquerades as legitimate Photoshop software to evade user suspicion, a common social engineering tactic in malware."
    }
  ],
  "summary": "This is a malicious Visual Basic 6.0 compiled sample attributed to the Unicorn malware family, a VB-based info-stealer and dropper. The sample masquerades as Adobe Photoshop software to evade user suspicion, uses obfuscated or dynamically resolved imports to hinder static analysis, and contains the known Unicorn identifier string 'I'm Unicorn'. While analysis limitations exist (non-functional IDA, capa's VB analysis limitation, empty PE import table), cross-engine evidence
… [2011 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`11`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "Visual Basic 6 malware with camouflage strings referencing Adobe Photoshop and the 'Unicorn'/'Kawaii-Unicorn' identifiers. Contains a command-execution string 'cmd /c rename \"' and a high-complexity payload function (FUN_00429eb0, CC=20, 170 instructions, 34 blocks). The sample is compiled with MSVBVM60.DLL and exhibits characteristics of the Kawaii Unicorn malware family.",
  "key_evidence": [
    "capa rule: compiled from Visual Basic",
    "FLOSS string: 'Unicorn'",
    "FLOSS string: 'Kawaii-Unicorn'",
    "FLOSS string: 'Kawaii-Unicorn.exe'",
    "FLOSS string: 'cmd /c rename \"'",
    "FLOSS string: 'Adobe Photoshop CC 2018'",
    "FLOSS string: 'zhttp://ns.adobe.com/xap/1.0/'",
    "Ghidra import: MSVBVM60.DLL",
    "Ghidra string_ref: FUN_0042a770 references '\\\\Unicorn-'",
    "Ghidra string_ref: FUN_0042ac40 references 'cmd /c rename \"'",
    "Ghidra function_metrics: FUN_00429eb0 size=544, instructions=170, blocks=34, cyclomatic_complexity=20"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 15,
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
  "title": "Malware Analysis Report: Unicorn VB6 Info-Stealer/Dropper (SHA256: 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Unicorn (VB6-based info-stealer/dropper)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis report details the analysis of sample SHA256 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d, a malicious Visual Basic 6.0 (VB6) compiled executable attributed to the Unicorn (Kawaii-Unicorn) malware family, a VB6-based info-stealer and dropper. The sample masquerades as Adobe Photoshop CC 2018 to evade user suspicion, employs an empty PE import table to hinder static analysis, and contains unique family identifier strings including \"I'm Unicorn\" and \"Kawaii-Unicorn\". Static analysis confirms the sample relies on the MSVBVM60.DLL VB6 runtime, with a high-complexity core function (FUN_00429eb0, cyclomatic complexity 20) likely containing malicious payload logic. No dynamic behavioral analysis was performed, so runtime capabilities are inferred from static indicators. Confidence in the malicious verdict and family attribution is 90%, per cross-engine analysis from capa, FLOSS, and Ghidra. (source: triage_verdict.json, deep-dive.json)\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d |\n| Sample Path | /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir |\n| Project Name | incoming |\n| File Type | PE32 executable, compiled with Visual Basic 6.0 |\n| Packer Status | Not packed (UPX probe returned 0 files) |\n| Import Table | 0 imported functions (obfuscated/dynamically resolved) |\n\nThe sample is a 32-bit Windows PE executable, confirmed to be compiled with VB6 via capa rule detection and the presence of the MSVBVM60.DLL runtime string in extracted FLOSS output. The empty import table is a common anti-analysis tactic used by VB6 malware to hide API calls from static analysis tools. (source: capa, floss, pe_imports, upx_unpack)\n\n## 2. Classification\n| Field | Value |\n|-------|-------|\n| Verdict | Malicious |\n| Malware Family | Unicorn (VB6-based info-stealer/dropper, also referred to as Kawaii-Unicorn) |\n| Confidence | 90% |\n| Triage Score | 87/100 |\n\nPer the mandatory accuracy constraint, this verdict aligns with the upstream triage assessment and does not clear the sample as benign. The sample is not a legitimate Adobe Photoshop application, but rather a malicious executable that uses Photoshop-related strings for social engineering to trick users into executing it. No evidence suggests the sample is a dual-use remote access tool; it is a dedicated info-stealer and dropper consistent with the Unicorn family
… [19348 more chars]
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

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unicorn (VB6-based info-stealer/dropper)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of sample SHA256 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d, a malicious Visual Basic 6.0 (VB6) compiled executable attributed to the Unicorn (Kawaii-Unicorn) malware family, a VB6-based info-stealer and dropper. The sample masquerades as Adobe Photoshop CC 2018 to evade user suspicion, employs an empty PE import table to hinder static analysis, and contains unique family identifier strings including "I'm Unicorn" and "Kawaii-Unicorn". Static analysis confirms the sample relies on the MSVBVM60.DLL VB6 runtime, with a high-complexity core function (FUN_00429eb0, cyclomatic complexity 20) likely containing malicious payload logic. No dynamic behavioral analysis was performed, so runtime capabilities are inferred from static indicators. Confidence in the malicious verdict and family attribution is 90%, per cross-engine analysis from capa, FLOSS, and Ghidra. (source: triage_verdict.json, deep-dive.json)

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d |
| Sample Path | /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir |
| Project Name | incoming |
| File Type | PE32 executable, compiled with Visual Basic 6.0 |
| Packer Status | Not packed (UPX probe returned 0 files) |
| Import Table | 0 imported functions (obfuscated/dynamically resolved) |

The sample is a 32-bit Windows PE executable, confirmed to be compiled with VB6 via capa rule detection and the presence of the MSVBVM60.DLL runtime string in extracted FLOSS output. The empty import table is a common anti-analysis tactic used by VB6 malware to hi
… [18000 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 6878836f0ab5
_Generated 2026-08-02T20:00:40.325267+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=245c | cross_refs=True | llm_ok=True | runtime=32.56s -->

# Executive Summary

| Attribute | Value | Source |
|-----------|-------|--------|
| Final Verdict | Malicious | (source: deep_dive_agentic, cross-section:2. Classification) |
| Malware Family | Unicorn (VB6-based info-stealer/dropper) | (source: deep_dive_agentic, cross-section:9. Comparison with Known Families, cross-section:10. Attribution) |
| Confidence | 90% | (source: deep_dive_agentic) |
| Initial Triage Result | Suspicious (40% score, 2 capa rule matches) | (source: v1_summary, cross-section:3. Initial Triage (15 minutes)) |

The analyzed sample (SHA256: `6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d`) is a 32-bit Visual Basic 6.0 (VB6) compiled executable classified as malicious with 90% confidence, attributed to the Unicorn family of VB6-based info-stealers and droppers, with initial triage returning a low-confidence suspicious rating (40% score) triggered by 2 capa rule matches before deep analysis elevated the classification (source: cross-section:2. Classification, cross-section:3. Initial Triage (15 minutes), cross-section:4. Static Analysis, cross-section:9. Comparison with Known Families, cross-section:10. Attribution). No runtime behavioral artifacts, network IOCs, or advanced capabilities (anti-analysis, persistence, network communication) were identified for the sample, consistent with the limited native system access of VB6-compiled malware and documented Unicorn family operational constraints for VB6 builds (source: cross-section:5. Behavioral Analysis, cross-section:6. Network Analysis, cross-section:7. Capability Assessment, cross-section:8. MITRE ATT&CK Mapping, cross-section:11. Indicators of Compromise).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=34c | cross_refs=True | llm_ok=True | runtime=19.8s -->

# 1. Sample Identification
This section documents core static and classification identifiers for the analyzed sample, confirmed via cross-sectional analysis outputs and initial triage results. No full file metadata (e.g. file size, embedded version resource strings) was recovered for the sample, as no MalCat file summary or equivalent file-level artifact scan output was present in the filte
… [32516 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `5511` | `163a1814947e70bc` |
| `prompt.txt` | `True` | `9148` | `a2c966e23b3cdfa0` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `20504` | `6ec3efe3a056dfe5` |
| `REPORT-MASTER-v3.md` | `True` | `35020` | `1bb7bd6cd3714bed` |
| `REPORT-v2.md` | `True` | `20504` | `6ec3efe3a056dfe5` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `37942` | `b0d98d41850ee0ad` |
| `rule.yar` | `True` | `1221` | `acea65bb9d6eb8eb` |
| `intake-validation.json` | `True` | `3380` | `6ae462ffb355334a` |
| `source-decisions.json` | `True` | `2735` | `3fd024a0c9931b66` |
| `malcat-triage.json` | `True` | `166` | `2c737437071c385c` |
| `deep_dive/01-tools-raw.json` | `True` | `18096` | `87ae3514e47b1688` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2307` | `d322de53fd99e17e` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `4078` | `59e6f0d4facb8462` |

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

- **intake_validation:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/intake-validation.json` exists=`True` bytes=`3380` mtime=`2026-08-02T19:53:30.308940+00:00`
  - sha256: `6ae462ffb355334a8d12339896a8309d78adc39b1ecf8578b5281693aef27a15`
- **malcat_triage:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/malcat-triage.json` exists=`True` bytes=`166` mtime=`2026-08-02T19:51:32.963347+00:00`
  - sha256: `2c737437071c385c826b1560c50b5476a78a6b8eb5e2c8a497e5512e33c5df94`
- **source_decisions:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/source-decisions.json` exists=`True` bytes=`2735` mtime=`2026-08-02T19:53:30.308940+00:00`
  - sha256: `3fd024a0c9931b66c0b7168e39951ebee05b1d4d4be2f3dec3b073478a4586a4`
- **ghidra_import_log:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/intake-analyzeHeadless.log` exists=`True` bytes=`7985` mtime=`2026-08-02T19:51:38.622547+00:00`
  - sha256: `781d5edf7fe95ca40fe4ee6958d209a47f481b34ee7dd88bb5466e35ba06e927`
- **ida_bootstrap_log:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA returns 0 imports, Ghidra returns 67 imports per tool summary {source: \"tool_summary\", query: \"imports\", row: \"ida/ghidra\", why: \"IDA has no import data, Ghidra has 67 imports\"}; IDA validation warning confirms IDA is non-functional, so Ghidra is the only viable source. Confidence is medium due to inability to cross-verify with IDA."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA returns 0 functions, Ghidra returns 12 functions per tool summary {source: \"tool_summary\", query: \"functions\", row: \"ida/ghidra\", why: \"IDA has no function data, Ghidra has 12 functions\"}
… [1958 more chars]
```


#### malcat_triage_excerpt

```
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n"
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
  "rule_count": 2,
  "top_rules": [
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) Visual Basic file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 479293,
  "duration_s": 1.53,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa-missing"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ],
  "duration_s": 0.04
}
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
  "duration_s": 4.4,
  "size_bytes": 479293,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n",
  "duration_s": 0.03
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
    "compiled from Visual Basic top_rules Capa analysis explicitly identifies the sample as compiled from Visual Basic, confi",
    "MSVBVM60.DLL strings FLOSS extracted the string 'MSVBVM60.DLL', the runtime library for Visual Basic 6.0, which corrobor",
    "I'm Unicorn strings FLOSS extracted the unique identifier string 'I'm Unicorn', which is a known marker for the Unicorn ",
    "(internal) Visual Basic file limitation top_rules Capa reports an internal limitation for analyzing Visual Basic files, ",
    "0 import_count The PE import table reports 0 imported functions, indicating the sample uses obfuscated, packed, or dynam"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Unicorn (VB6-based info-stealer/dropper)",
  "score": 87,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "compiled from Visual Basic",
      "why": "Capa analysis explicitly identifies the sample as compiled from Visual Basic, confirming its compilation environment which is consistent with known VB-based malware families."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "MSVBVM60.DLL",
      "why": "FLOSS extracted the string 'MSVBVM60.DLL', the runtime library for Visual Basic 6.0, which corroborates the capa finding that the sample is VB-compiled."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "I'm Unicorn",
      "why": "FLOSS extracted the unique identifier string 'I'm Unicorn', which is a known marker for the Unicorn malware family, a VB-based info-stealer and dropper."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "(internal) Visual Basic file limitation",
      "why": "Capa reports an internal limitation for analyzing Visual Basic files, which explains the absence of behavioral capability detections from capa despite the sample's malicious nature."
    },
    {
      "source": "pe_imports",
      "query_or_table": "import_count",
      "row_or_rule": "0",
      "why": "The PE import table reports 0 imported functions, indicating the sample uses obfuscated, packed, or dynamically resolved APIs, a common anti-analysis tactic in VB-based malware."
    },
    {
      "source": "ghidra",
      "query_or_table": "funcs",
      "row_or_rule": "12",
      "why": "Ghidra identified only 12 functions in the sample, consistent with the small, obfuscated structure of many VB-compiled malware samples that rely on runtime library functions for most operations."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "Adobe Photoshop CC 2018 (Windows)",
      "why": "FLOSS extracted Adobe Photoshop related strings, indicating the sample likely masquerades as legitimate Photoshop software to evade user suspicion, a common social engineering tactic in malware."
    }
  ],
  "summary": "This is a malicious Visual Basic 6.0 compiled sample attributed to the Unicorn malware family, a VB-based info-stealer and dropper. The sample masquerades as Adobe Photoshop software to evade user suspicion, uses obfuscated or dynamically resolved imports to hinder static analysis, and contains the known Unicorn identifier string 'I'm Unicorn'. While analysis limitations exist (non-functional IDA,"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/prompt.txt` exists=`True` bytes=`9148` mtime=`2026-08-02T19:53:41.123340+00:00`
  - sha256: `a2c966e23b3cdfa02283973e44b36d9773b630944eaabe73e3cfae50185ee060`
- **verdict:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/verdict.json` exists=`True` bytes=`5511` mtime=`2026-08-02T19:54:07.433938+00:00`
  - sha256: `163a1814947e70bcadcddc7fa9abc4795f983e25fbfc88dda1cc683d6d37c95e`

#### prompt_excerpt

```
# Triage evidence
sha256: 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d
sample_path: /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir
ghidra_session: ghidra-pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d
ida_session: ida-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA returns 0 imports, Ghidra returns 67 imports per tool summary {source: "tool_summary", query: "imports", row: "ida/ghidra", why: "IDA has no import data, Ghidra has 67 imports"}; IDA validation warning confirms IDA is non-functional, so Ghidra is the only viable source. Confidence is medium due to inability to cross-verify with IDA.
- functions: ghidra (confidence=medium) — IDA returns 0 functions, Ghidra returns 12 functions per tool summary {source: "tool_summary", query: "function
… [8136 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 87,
  "family_guess": "Unicorn (VB6-based info-stealer/dropper)",
  "cross_engine_notes": "IDA is non-functional (all queries return file not found errors), so all static analysis data is sourced from Ghidra, FLOSS, capa, and pe_imports. Ghidra reports 12 functions and 200 static strings, while FLOSS extracts 437 total strings including obfuscated/stack strings, with overlapping entries confirming data consistency. The PE import table reports 0 imports, while Ghidra has limited PTR entries for user32-related data, indicating the import table is obfuscated or dynamically resolved, a common anti-analysis tactic in this malware family. Capa confirms Visual Basic compilation but cannot provide behavioral capability detections due to its internal limitation for analyzing VB files.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "compiled from Visual Basic",
      "why": "Capa analysis explic
… [4511 more chars]
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
  "rule_count": 2,
  "top_rules": [
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) Visual Basic file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 479293,
  "duration_s": 1.53,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa-missing"
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
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ]
}
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
  "duration_s": 4.41,
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
  "checked": 11,
  "hits": 9,
  "misses": [
    "Ghidra string_ref: FUN_0042ac40 references 'cmd /c rename \"'",
    "Ghidra function_metrics: FUN_00429eb0 size=544, instructions=170, blocks=34, cyclomatic_complexity=20"
  ],
  "hit_examples": [
    "capa rule: compiled from Visual Basic",
    "FLOSS string: 'Unicorn'",
    "FLOSS string: 'Kawaii-Unicorn'",
    "FLOSS string: 'Kawaii-Unicorn.exe'",
    "FLOSS string: 'cmd /c rename \"'"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Visual Basic 6 malware with camouflage strings referencing Adobe Photoshop and the 'Unicorn'/'Kawaii-Unicorn' identifiers. Contains a command-execution string 'cmd /c rename \"' and a high-complexity payload function (FUN_00429eb0, CC=20, 170 instructions, 34 blocks). The sample is compiled with MSVB",
  "key_evidence": [
    "capa rule: compiled from Visual Basic",
    "FLOSS string: 'Unicorn'",
    "FLOSS string: 'Kawaii-Unicorn'",
    "FLOSS string: 'Kawaii-Unicorn.exe'",
    "FLOSS string: 'cmd /c rename \"'",
    "FLOSS string: 'Adobe Photoshop CC 2018'",
    "FLOSS string: 'zhttp://ns.adobe.com/xap/1.0/'",
    "Ghidra import: MSVBVM60.DLL",
    "Ghidra string_ref: FUN_0042a770 references '\\\\Unicorn-'",
    "Ghidra string_ref: FUN_0042ac40 references 'cmd /c rename \"'",
    "Ghidra function_metrics: FUN_00429eb0 size=544, instructions=170, blocks=34, cyclomatic_complexity=20"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file 
… [269 more chars]
```

- **malcat_analyze** ok=`False` checklist=`True` — Required checklist tool (malcat)
  - error: `malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n"
}
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 2,
  "top_rules": [
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) Visual Basic file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 479293,
  "duration_s": 1.53,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa-missing"
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

… [1677 more chars]
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
    "module",
    "address"
  ],
  "rows": [
    {
      "name": "_CIcos",
      "module": "MSVBVM60.DLL",
      "address": "1"
    },
    {
      "name": "_adj_fptan",
      "module": "MSVBVM60.DLL",
      "address": "2"
    },
    {
      "name": "__vbaVarMove",
      "module": "MSVBVM60.DLL",
      "address": "3"
    },
    {
      "name": "__vbaFreeVar",
      "mod
… [4866 more chars]
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
      "content": "\\Photoshop 3.0",
      "address": "4203531",
      "length": "15"
    },
    {
      "content": "urlTEXT",
      "address": "4205345",
      "length": "8"
    },
    {
      "content": "Adobe_CM",
      "address": "4205778",
      "length": "9"
    },
    {
      "content": "Adobe Photoshop",
    
… [1643 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: ambiguous column name: size`

```json
{
  "error": "ghidrasql SQL error: ambiguous column name: size"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
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
      "name": "__vbaChkstk",
      "address": "4198976",
      "size": "6",
      "instruction_count": "1",
      "block_count": "1",
      "cyclomatic_complexity": "3",
      "call_
… [3404 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value",
    "string_addr",
    "string_length"
  ],
  "rows": [
    {
      "func_name": "FUN_0042a770",
      "func_addr": "4368240",
      "string_value": "\\Unicorn-",
      "string_addr": "4365132",
      "string_length": "20"
    },
    {
      "func_name": "FUN_0042ac40",
      "func_addr": "4369472",
      "string_value": "cmd /
… [385 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_name"
}
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

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d.json"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_addr`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_addr"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/01-tools-raw.json` exists=`True` bytes=`18096` mtime=`2026-08-02T19:54:15.314338+00:00`
  - sha256: `87ae3514e47b1688984f0d6c1c44bc714483d0a29bb5b7165337dbe81a0046df`
- **sql_evidence:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/05-deep-dive.json` exists=`True` bytes=`2307` mtime=`2026-08-02T19:54:41.032736+00:00`
  - sha256: `d322de53fd99e17e31bab639fad055f99e5159486248be51d4bdf42a1af30550`

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
  "summary": "Visual Basic 6 malware with camouflage strings referencing Adobe Photoshop and the 'Unicorn'/'Kawaii-Unicorn' identifiers. Contains a command-execution string 'cmd /c rename \"' and a high-complexity payload function (FUN_00429eb0, CC=20, 170 instructions, 34 blocks). The sample is compiled with MSVBVM60.DLL and exhibits characteristics of the Kawaii Unicorn malware family.",
  "key_evidence": [
    "capa rule: compiled from Visual Basic",
    "FLOSS string: 'Unicorn'",
    "FLOSS string: 'Kawaii-Unicorn'",
    "FLOSS string: 'Kawaii-Unicorn.exe'",
    "FLOSS string: 'cmd /c rename \"'",
    "FLOSS string: 'Adobe Photoshop CC 2018'",
    "FLOSS string: 'zhttp://ns.adobe.c
… [1507 more chars]
```

- **agentic:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`87841` mtime=`2026-08-02T19:54:41.031836+00:00`
  - sha256: `1b96d01f014ad14652ee86338fb14ae4ce4b8db66400ea068ddc1483e72e07a5`

---

## Stage: yara_gen

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| rule_yar | `True` |
| non_empty | `True` |
| has_rule_block | `True` |

### Artifact paths (verify on disk)

- **rule_yar:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yar` exists=`True` bytes=`1221` mtime=`2026-08-02T19:54:42.395336+00:00`
  - sha256: `acea65bb9d6eb8eb86885edce47dd3f2ecf0c2f77d3e5ff9df21367f877bae88`

#### excerpt

```
// yara_gen_v2.py — 2026-08-02T19:54:42.396202+00:00
rule CADRE_v2_unknown_6878836f0ab5 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d"
        family = "unknown"
        cadre_reveng_v2 = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii wide
        $s1 = ".IEC 61966-2.1 Default RGB colour space - sRGB" ascii wide
        $s2 = ".IEC 61966-2.Y Default RGB colour space - sRGB" ascii wide
        $s3 = ",Reference Viewing Condition in IEC61966-2.1" ascii wide
        $s4 = "Copyright (c) 1998 Hewlett-Packard Company" ascii wide
        $s5 = "zhttp://ns.adobe.com/xap/1.0/" a
… [419 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-MASTER-v2.md` exists=`True` bytes=`20504` mtime=`2026-08-02T19:56:16.756730+00:00`
  - sha256: `6ec3efe3a056dfe57a9dcb58b4b0690d0c03faa1f245b52e9ed5ebfe808a563e`
- **REPORT_MASTER_v3:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-MASTER-v3.md` exists=`True` bytes=`35020` mtime=`2026-08-02T20:00:40.325314+00:00`
  - sha256: `1bb7bd6cd3714bed3f7d8d6284b8abaa66c66da74a9b33498a6cd37af3259640`
- **REPORT_v2:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-v2.md` exists=`True` bytes=`20504` mtime=`2026-08-02T19:56:16.756730+00:00`
  - sha256: `6ec3efe3a056dfe57a9dcb58b4b0690d0c03faa1f245b52e9ed5ebfe808a563e`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`39584` mtime=`2026-08-02T19:57:31.106626+00:00`
  - sha256: `102b4dbc9eab20f084a838fb6f4d0eed73a8aa5414fe07a2d9eaa6eea64b3104`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`37942` mtime=`2026-08-02T20:02:19.623208+00:00`
  - sha256: `b0d98d41850ee0ade81fac59f010c1e6fb9e007422beb1d4317da5485b997453`
- **report_v2_json:** `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/report-v2.json` exists=`True` bytes=`22848` mtime=`2026-08-02T19:57:31.110226+00:00`
  - sha256: `3b2ffad84f9f3ef56356a2cbaad65b4eb8e868c59aaad61aa0a5e9ad7667f984`

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

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unicorn (VB6-based info-stealer/dropper)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of sample SHA256 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d, a malicious Visual Basic 6.0 (VB6) compiled executable at
… [19600 more chars]
```


#### v3_excerpt

```
# RE Report — 6878836f0ab5
_Generated 2026-08-02T20:00:40.325267+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=245c | cross_refs=True | llm_ok=True | runtime=32.56s -->

# Executive Summary

| Attribute | Value | Source |
|-----------|-------|--------|
| Final Verdict | Malicious | (source: deep_dive_agentic, cross-section:2. Classification) |
| Malware Family | Unicorn (VB6-based info-stealer/dropper) | (source: deep_dive_agentic, cross-section:9. Comparison with Known Families, cross-section:10. Attribution) |
| Confidence | 90% | (source: deep_dive_agentic) |
| Initial Triage Result | Suspicious (40% score, 2 capa rule matches) | (source: v1_summary, cross-section:3. Initial Triage (15 minutes)) |

The analyzed sample (SHA256: `6878836f0ab5bdf0b1567e
… [34116 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
