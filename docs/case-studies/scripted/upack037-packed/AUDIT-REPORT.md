# Pipeline AUDIT-REPORT — `36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:25.396032+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:25 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9`

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

- source=`llm_judge` verdict=`suspicious` confidence=`60`
- key_evidence_count=`6`

```json
{
  "verdict": "suspicious",
  "score": 60,
  "family_guess": "Upack",
  "cross_engine_notes": "Discrepancies between Ghidra and IDA in function and string counts (0 vs 1 functions, 22 vs 229 strings) suggest packing or obfuscation; Ghidra found no imports while IDA found 2, aligning with Malcat's NoImportTable anomaly. Capa failed due to corrupt PE header, indicating high obfuscation.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "Packed",
      "why": "Malcat anomaly 'Packed' indicates the file is packed using an obfuscator, a neutral but common technique in malware to hinder analysis."
    },
    {
      "source": "packer_intake",
      "query_or_table": "packer_intake checks",
      "row_or_rule": "score=8",
      "why": "Packer_intake score of 8 based on high entropy in executable sections and raw vs virtual size mismatches, indicating packing or obfuscation."
    },
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "Upack_V037_Dwing",
      "why": "YARA rule matches known Upack packer signature, confirming the use of a packer, which is a neutral obfuscation signal but often associated with malware."
    },
    {
      "source": "ida",
      "query_or_table": "imports",
      "row_or_rule": "LoadLibraryA and GetProcAddress",
      "why": "IDA shows only these two imports, which are commonly used for dynamic function resolution in packed or malicious code to evade static analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "NoImportTable",
      "why": "Lack of a valid import table is typical in packed executables where imports are resolved dynamically at runtime, adding to obfuscation."
    },
    {
      "source": "capa",
      "query_or_table": "capa error",
      "row_or_rule": "corrupt header",
      "why": "Capa failed to parse the PE file due to a corrupt header, suggesting heavy obfuscation or packing that prevents standard analysis tools from functioning."
    }
  ],
  "summary": "The sample is a packed PE executable identified as Upack 037, with multiple anomalies from Malcat and YARA indicating obfuscation techniques. IDA reveals minimal imports for dynamic loading, and Capa fails due to corrupt headers. No clear behavioral-intent evidence (e.g., C2, persistence, or malicious strings) was found; thus, it is suspicious based solely on obfuscation and packing signals, which are neutral but common in malware.",
  "source": "llm_judge",
  "model": "configured-llm",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "malicious",
    "score": 250,
    "findings": [
      "yara: 21 matches"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "malicious",
    "score": 250,
    "findings": [
      "yara: 21 matches"
    ]
  },
  "tool_gate": {
    "ok": false,
    "format": "dotnet",
    "required": [
      "capa",
      "yara",
      "malcat",
      "floss",
      "pe_imports"
    ],
    "tools": {
      "capa": {
        "ok": false,
        "why": "capa_incomplete:capa rc=13"
      },
      "yara": {
        "ok": true,
        "why": "ok"
      },
      "floss": {
        "ok": false,
        "why": "floss_incomplete:floss rc=1:\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u25
… [2562 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`10`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This sample is a packed executable using Upack v0.37 packer that masquerades as Windows Calculator (CALC.EXE) from Microsoft Corporation. The PE header is intentionally corrupted (capa reports 'data at RVA can't be fetched. Corrupt header?'), characteristic of Upack-packed files. Only two imports exist (LoadLibraryA and GetProcAddress), which is the classic packer stub pattern for dynamic API resolution to evade static analysis. All memory segments are marked RWX (read/write/execute), indicating self-modifying code behavior. The file contains embedded IP addresses (IPv4/IPv6), domain patterns, and base64-encoded content detected by YARA. FLOSS failed to extract stack strings due to the corrupted PE structure. Version info metadata (Microsoft Corporation, Windows Calculator) is a masquerade - 21 YARA rules definitively match Upack packer signatures. The true payload is hidden beneath the packer and would execute dynamically at runtime.",
  "key_evidence": [
    "YARA: 21 rules matched including WinUpackv039finalByDwing, UpackV037Dwing, Upack_V037_V039_Dwing, Upack_v039_final - definitive Upack packer identification",
    "IDA imports: Only KERNEL32!LoadLibraryA (0x1001828) and KERNEL32!GetProcAddress (0x100182C) - classic packer stub with dynamic API resolution",
    "capa error: 'data at RVA can't be fetched. Corrupt header?' - PE structure intentionally corrupted by Upack packer",
    "Ghidra memory_blocks: All 3 code segments (PS______, seg003, M_____) have perm=7 (RWX) - indicates self-modifying/unpacking code",
    "YARA: HasOverlay, HasModified_DOS_Message - packer structural anomalies",
    "YARA: domain rule matched at offset 0, IPv4 at offset 2212, IPv6 at offset 6028 - embedded network indicators",
    "YARA: contains_base64 matched at offset 42 - encoded content in payload",
    "Ghidra strings: Version info masquerades as 'Windows Calculator application file' by 'Microsoft Corporation' v5.1.2600.0, OriginalFilename='CALC.EXE' - brand spoofing",
    "FLOSS failure: 'TypeError: a bytes-like object is required, not NoneType' - PE corruption prevents stack string extraction",
    "File labeled as 'dotnet' type but packed with Upack native packer - likely .NET payload wrapped in native packer shell"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 22,
  "successful_non_bootstrap_tools": 15,
  "checklist_ok": true,
  "sql_deep_ok": true,
  "tool_gate": {
    "ok": true,
    "format": "dotnet",
    "required": [
      "capa",
      "pe_imports",
      "yara",
      "floss",
      "dotnet",
      "r2_decomp",
      "upx",
      "xor",
      "frida_probe"
    ],
    "tools": {
      "capa": {
        "ok": false,
        "why": "soft_fail_packed:capa_incomplete:capa rc=13",
        "soft": true,
        "packer": "packed"
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
        "ok": false,
        "why": "soft_fail_packed:floss_incomplete:floss rc=1:\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f    \u2502\n\u2570\u2500\u2500
… [1384 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Upack 037 Packed Executable",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-09 23:47:54 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | suspicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: WinUpackv039finalByDwingc2005h1, Upackv039finalDwing, UpackV037Dwing, IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message, WinUpack_v039_final_By_Dwing_c2005_additional). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Upack\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Malware Analysis Report: Upack 037 Packed Executable\n\n## Executive Summary\n\nThis report details the analysis of a suspicious executable (SHA256: 36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9) identified as a packed PE file using the Upack v0.37 packer. The sample exhibits significant obfuscation and anti-analysis characteristics, including a corrupted PE header, minimal static imports, and all memory segments marked as executable. While no direct malicious behavior (e.g., C2 communication, data exfiltration, or persistence mechanisms) was observed in the available static analysis, the combination of packer usage, masquerade as a legitimate Windows Calculator application, and embedded network indicators strongly suggests malicious intent. The verdict is **suspicious** based on the current evidence, with high confidence that the true payload is hidden and would execute dynamically at runtime. Further dynamic analysis is required to confirm the exact malicious capabilities.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| SHA256 | 36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9 |\n| File Path | /opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe |\n| Project | REVAI-LAB-CORPUS-H1 |\n| File Type | PE32 Executable (GUI) Intel 80386, for MS Windows |\n| Architecture | x86 |\n| Packer | Upack v0.37 (confirmed by YARA) |\n| Original Filename | CALC.EXE (masquerade) |\n| Version Info | Microsoft Corporation, Windows Calculator, v5.1.2600.0 |\n| Entropy | High (156) |\n| Size | 36,864 bytes (approx.) |\n\nThe sample is a 32-bit Windows executable that has been packed with Upack, a known packer often used to obfuscate malware. The version information masquerades as the legitimate Windows Calculator application from Microsoft, a common social engineering tactic. (source: malcat, yara)\n\n## 2. Classification\n\n**Verdict: Suspicious**\n\n**Confidence: 90%**\n\n**Family: Upack (Packer)**\n\nThe classification is based on the following key evidence:\n1.  **Packer Identification:** 21 YARA rules definitively match signatures for the Upack packer (v0.37 and v0.39 variants). (source: yara)\n2.  **Obfuscation Indicators:** The PE header is intentionally corrupted, preventing standard analysis tool
… [17010 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 23:47:54 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: WinUpackv039finalByDwingc2005h1, Upackv039finalDwing, UpackV037Dwing, IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message, WinUpack_v039_final_By_Dwing_c2005_additional). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Upack
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Upack 037 Packed Executable

## Executive Summary

This report details the analysis of a suspicious executable (SHA256: 36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9) identified as a packed PE file using the Upack v0.37 packer. The sample exhibits significant obfuscation and anti-analysis characteristics, including a corrupted PE header, minimal static imports, and all memory segments marked as executable. While no direct malicious behavior (e.g., C2 communication, data exfiltration, or persistence mechanisms) was observed in the available static analysis, the combination of packer usage, masquerade as a legitimate Windows Calculator application, and embedded network indicators strongly suggests malicious intent. The verdict is **suspicious** based on the current evidence, with high confidence that the true payload is hidden and would execute dynamically at runtime. Further dynamic analysis is required to confirm the exact malicious capabilities.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| SHA256 | 36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9 |
| File Path | /opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe |
| Project | REVAI-LAB-CORPUS-H1 |
| File Type | PE32 Executable (GUI) Intel 80386, for MS Windows |
| Architecture | x86 |
| Packer | Upack v0.37 (confirmed by YARA) |
| Original Filename | CALC.EXE (
… [14802 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 23:54:55 UTC

# RE Report — 36137a22c973
_Generated 2026-08-09T23:54:55.640044+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=214c | cross_refs=True | llm_ok=True | runtime=43.35s -->

**Executive Summary**

The sample with SHA256 `36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9` is assessed as **suspicious** with indicators pointing towards malicious intent, likely associated with the **Upack** family, a known packer for obfuscating malware. Confidence in this assessment is high, supported by a deep analysis with a confidence score of 90. The sample exhibits obfuscation techniques typical of packed malware, but direct malicious activity remains unconfirmed without dynamic analysis.

Key findings are summarized below:

| Aspect | Assessment | Evidence & Interpretation |
|--------|------------|---------------------------|
| **Verdict** | Suspicious (primary); initial LLM assessment as malicious but in disagreement. | The primary verdict is 'suspicious' (source: evidence, verdict: suspicious), while an initial LLM analysis scored it as 'malicious' with 250 points based on 21 YARA matches (source: evidence, v1_summary: verdict: malicious, score: 250, findings: ['yara: 21 matches']). The 'llm_v1_disagree' status indicates a discrepancy, suggesting the need for further validation (source: evidence, agreement: llm_v1_disagree). We assess this as a potential false positive or overcaution, requiring deeper investigation. |
| **Family** | Upack | The sample is likely associated with the Upack packer family, based on initial family guess and cross-section analysis (source: evidence, family_guess: Upack; source: cross-section:3. Background & Family Lineage, citation: family_guess). Upack is commonly used to obfuscate malware payloads, complicating detection (source: cross-section:3. Background & Family Lineage, why: known packer for malware obfuscation). |
| **Confidence** | High (90) | Deep analysis from a trusted source (source: evidence, deep_confidence: 90, deep_source: deep_dive_agentic) provides high confidence in the suspicious assessment, though the disagreement with the initial LLM adds nuance. |

The 21 YARA matches indicate common malware patt
… [42218 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6062` | `c59338d08901f285` |
| `prompt.txt` | `True` | `19065` | `9349124ce1f1bf38` |
| `pipeline-audit.json` | `True` | `109025` | `ccc4f91a9aff1de6` |
| `AUDIT-REPORT.md` | `True` | `80526` | `899605a98cd2110b` |
| `REPORT-MASTER-v2.md` | `True` | `17311` | `b2779cb64e958a59` |
| `REPORT-MASTER-v3.md` | `True` | `44741` | `951dc79fd7a31e2b` |
| `REPORT-v2.md` | `True` | `17311` | `b2779cb64e958a59` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `40615` | `142a5ce03742aacb` |
| `rule.yar` | `True` | `1206` | `8cf08d5411626564` |
| `intake-validation.json` | `True` | `2281` | `543d9c23eaae65e9` |
| `source-decisions.json` | `True` | `1270` | `7abf9e53926f4594` |
| `malcat-triage.json` | `True` | `17283` | `8fdf283dbe88eea6` |
| `deep_dive/01-tools-raw.json` | `True` | `81640` | `baeea5521dd6d2ca` |
| `deep_dive/01-tools-gate.json` | `True` | `2176` | `fffad6e31633a905` |
| `deep_dive/05-deep-dive.json` | `True` | `4884` | `2a2808791780be74` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `68071` | `7b8b745320c40d22` |

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

- **intake_validation:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/intake-validation.json` exists=`True` bytes=`2281` mtime=`2026-08-09T14:29:36.936889+00:00`
  - sha256: `543d9c23eaae65e95aa6c33fe0ab357ca6fd235fc4e16c760f0f724cbe00c420`
- **malcat_triage:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/malcat-triage.json` exists=`True` bytes=`17283` mtime=`2026-08-09T14:28:50.903820+00:00`
  - sha256: `8fdf283dbe88eea6e4fe9c637a9df9bda3e043c5022aa3069bffc5fc3a8ace6b`
- **source_decisions:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/source-decisions.json` exists=`True` bytes=`1270` mtime=`2026-08-09T14:29:36.936889+00:00`
  - sha256: `7abf9e53926f45943b85d6a2ce176bbc3cadd7c084e02a572da79509d8e6433b`
- **ghidra_import_log:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/intake-analyzeHeadless.log` exists=`True` bytes=`46026` mtime=`2026-08-09T13:03:26.227671+00:00`
  - sha256: `694a9971a5ff4d15032290bf1199dfe62cf79c2de15c99e1111e55a34e06defe`
- **ida_bootstrap_log:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/intake-idasql.log` exists=`True` bytes=`231` mtime=`2026-08-09T14:28:52.067819+00:00`
  - sha256: `6c7fdf233590535c3bbee6c7805426b6b13981d17c8d51b34c3ce3d14fdb01f5`

#### source_decisions_excerpt

```
{
  "sha256": "36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
  "imports": {
    "source": "ida",
    "confidence": "medium",
    "reason": "IDA has 2 imports while Ghidra and Malcat show 0; likely a packed/binder PE with imports in embedded sub-PEs, as per warning."
  },
  "functions": {
    "source": "ida",
    "confidence": "medium",
    "reason": "IDA has 1 function while Ghidra and Malcat show 0; divergence noted in warning indicates potential complexity."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Use both engines to capture a broader set of strings; IDA reports 229 strings, Ghidra 22, and Malcat 100."
  },
  "decompilation": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Default to Ghidra for decompila
… [493 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
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
    "file_name": "Upack037.exe",
    "file_path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
    "file_size": 52224,
    "type": "PE",
    "architecture": "X86",
    "entropy": 156,
    "sha256": "36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
    "metadata": {},
    "entrypoint_ea": 86040,
    "layout": [
      {
        "na
… [16483 more chars]
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

#### `capa` — ok=`True` why=`packed_soft:packed:error:capa rc=13`

```json
{
  "error": "capa rc=13",
  "stderr": "ERROR    capa: Input file '/opt/samples/corpus/CTF 1 - Weeks   main.py:563\n         1-8/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f            \n         10ad013c9/Upack037.exe' is not a valid PE file: \"data at               \n         RVA can't be fetched. Corrupt header?\"                                 \n",
  "timeout_s": 300,
  "sample_size": 52224,
  "duration_s": 1.47,
  "engine": "capa"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 21,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 2212,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 6028,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 42,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "WinUpackv039finalByDwingc2005h1",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 24,
          "length": 84,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Upackv039finalDwing",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 240,
          "length": 23,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 160,
          "length": 23,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UpackV037Dwing",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 40,
          "length": 168,
          "xor_key": null
        },
        {
          "id": "$a2",
          "offset": 24,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "WinUpack_v039_final_By_Dwing_c2005_additional",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 24,
          "length": 321,
  
… [6750 more chars]
```

#### `floss` — ok=`True` why=`fail_open:floss rc=1:────────────────────────────────────────────────────╯    │
╰──────────────────────────────────────────────────────────────────────────────╯
TypeError: a bytes-like object is required, not 'NoneType'

`

```json
{
  "floss_ok": false,
  "static_only": true,
  "size_bytes": 52224,
  "size_exceeded_deobfuscate_limit": false,
  "fallback": "strings(1)",
  "fail_open": true,
  "reason": "floss rc=1:\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f    \u2502\n\u2570\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f\nTypeError: a bytes-like object is required, not 'NoneType'\n\n",
  "error": "floss rc=1:\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f    \u2502\n\u2570\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f\nTypeError: a bytes-like object is required, not 'NoneType'\n\n",
  "floss_profile": "full",
  "static_strings": [
    "MZKERNEL32.DLL",
    "LoadLibraryA",
    "GetProcAddress",
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">",
    "<assemblyIdentity",
    "name=\"Microsoft.Windows.Shell.calc\"",
    "processorArchitecture=\"x86\"",
    "version=\"5.1.0.0\"",
    "type=\"win32\"/>",
    "<description>Windows Shell</description>",
    "<dependency>",
    "<dependentAssembly>",
    "<assemblyIdentity",
    "type=\"win32\"",
    "name=\"Microsoft.Windows.Common-Controls\"",
    "version=\"6.0.0.0\"",
    "processorArchitecture=\"x86\"",
    "publicKeyToken=\"6595b64144ccf1df\"",
    "language=\"*\"",
    "</dependentAssembly>",
    "</dependency>",
    "</assembly>",
    "dDDDDDDDDDDDDD@",
    "fffffffffffff@",
    "opopopopowwpf@",
    "fffffffffffff@",
    "opopopopopopf@",
    "fffffffffffff@",
    "opopopopopopf@",
    "fffffffffffff@",
    "`wwwwwwwfffff@",
    "`wwwwwwwfffff@",
    "ffffffffffffffa",
    "fDDDDDD@offffff@n`",
    "p@offffff@n`",
    "@offffff@n",
    "|||ddcO87",
    "=||ccOM7",
    "`NfOM79|?4",
    "xrssssvvvv",
    "^zwurqqqqqsssssvvvv;",
    "^;LLZZzxxwtrqqrZ",
    "*4!XT?=,",
    "![kT@2P?.,",
    "cDfLMGN^J",
    "n?UKVWXC;",
    "FBA23>@S",
    "u&NU@[nAJ",
    "8cKFT/|,d",
    "#6I,;VRUw",
    "U2h\tS+J$w"
  ],
  "static_string_count": 52,
  "strings": [
    "MZKERNEL32.DLL",
    "LoadLibraryA",
    "GetProcAddress",
    "<?xml version=\"1.0\" en
… [1323 more chars]
```

#### `malcat` — ok=`True` why=`not_applicable:dotnet`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
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
    "file_name": "Upack037.exe",
    "file_path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
    "file_size": 52224,
    "type": "PE",
    "architecture": "X86",
    "entropy": 156,
    "sha256": "36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
    "metadata": {},
    "entrypoint_ea": 86040,
    "layout": [
      {
        "name": "M\u00f7\u0001\u0001\u00fc\u000f",
        "effective_address": 0,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RWX",
        "entropy": 132
      },
      {
        "name": "",
        "effective_address": 4096,
        "physical_size": 51712,
        "virtual_size": 81920,
        "rights": "RWX",
        "entropy": 156
      },
      {
        "name": "PS\u00ff\u00d5\u00ab\u00eb\u00e7\u00c3",
        "effective_address": 86016,
        "physical_size": 0,
        "virtual_size": 126976,
        "rights": "RWX",
        "entropy": 0
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "DataBetweenHeaderAndFirstSection",
        "desc": "There is non-zero data between the PE header and the first section",
        "category": "headers",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "ExtraSpaceAfterResourcesDataDirectory",
        "desc": "extra physical data in rsrc section after resource directory data",
        "category": "resources",
        "level": 4,
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
        "name": "InvalidBaseOfCode",
        "desc": "at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section",
        "category": "sections",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "InvalidSizeOfCode",
        "desc": "SizeofCode is not the sum of all code sections (raw or virtual)",
        "category": "sections",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "InvalidSizeOfInitializedData",
        "desc": "SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual)",
        "category": "sections",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "InvalidSizeOfUninitializedData",
        "desc": "SizeOfUninitializedData is not the sum of all uninitalized data sections (raw or virtual)",
        "category": "sections",
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
        "name": "NoImportTable",
        "desc": "no valid Import Table found",
        "category": "imports",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "Packed",
        "desc": "File
… [41483 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "Packed anomalies Malcat anomaly 'Packed' indicates the file is packed using an obfuscator, a neutral but common techniqu",
    "score=8 packer_intake checks Packer_intake score of 8 based on high entropy in executable sections and raw vs virtual si",
    "Upack_V037_Dwing YARA matches YARA rule matches known Upack packer signature, confirming the use of a packer, which is a",
    "LoadLibraryA and GetProcAddress imports IDA shows only these two imports, which are commonly used for dynamic function r",
    "NoImportTable anomalies Lack of a valid import table is typical in packed executables where imports are resolved dynamic"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "suspicious",
  "family": "Upack",
  "score": 60,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "configured-llm",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "Packed",
      "why": "Malcat anomaly 'Packed' indicates the file is packed using an obfuscator, a neutral but common technique in malware to hinder analysis."
    },
    {
      "source": "packer_intake",
      "query_or_table": "packer_intake checks",
      "row_or_rule": "score=8",
      "why": "Packer_intake score of 8 based on high entropy in executable sections and raw vs virtual size mismatches, indicating packing or obfuscation."
    },
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "Upack_V037_Dwing",
      "why": "YARA rule matches known Upack packer signature, confirming the use of a packer, which is a neutral obfuscation signal but often associated with malware."
    },
    {
      "source": "ida",
      "query_or_table": "imports",
      "row_or_rule": "LoadLibraryA and GetProcAddress",
      "why": "IDA shows only these two imports, which are commonly used for dynamic function resolution in packed or malicious code to evade static analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "NoImportTable",
      "why": "Lack of a valid import table is typical in packed executables where imports are resolved dynamically at runtime, adding to obfuscation."
    },
    {
      "source": "capa",
      "query_or_table": "capa error",
      "row_or_rule": "corrupt header",
      "why": "Capa failed to parse the PE file due to a corrupt header, suggesting heavy obfuscation or packing that prevents standard analysis tools from functioning."
    }
  ],
  "summary": "The sample is a packed PE executable identified as Upack 037, with multiple anomalies from Malcat and YARA indicating obfuscation techniques. IDA reveals minimal imports for dynamic loading, and Capa fails due to corrupt headers. No clear behavioral-intent evidence (e.g., C2, persistence, or malicious strings) was found; thus, it is suspicious based solely on obfuscation and packing signals, which"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/prompt.txt` exists=`True` bytes=`19065` mtime=`2026-08-09T21:23:13.069734+00:00`
  - sha256: `9349124ce1f1bf382e2278f51f5060a0f47914e0d93b3e4b5ff44d100ed70115`
- **verdict:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/verdict.json` exists=`True` bytes=`6062` mtime=`2026-08-09T21:23:54.324701+00:00`
  - sha256: `c59338d08901f285526c5872bb9c0f42ae20a415aa3c807890cebe78f4b8432f`

#### prompt_excerpt

```
# Triage evidence
sha256: 36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9
sample_path: /opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe
ghidra_session: ghidra-dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9
ida_session: ida-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9

## Source decisions (from intake validation)
- imports: ida (confidence=medium) — IDA has 2 imports while Ghidra and Malcat show 0; likely a packed/binder PE with imports in embedded sub-PEs, as per warning.
- functions: ida (confidence=medium) — IDA has 1 function while Ghidra and Malcat show 0; divergence noted in warning indicates potential complexity.
- strings: both (confidence=high) — Use both engines to capture a broader set of strings; IDA reports 229 strings, Ghidra 22, and Malcat 100.
- decompilation: ghidra (confidence=medium) — Default to Ghidra for decompilation as no specific
… [18034 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "suspicious",
  "score": 60,
  "family_guess": "Upack",
  "cross_engine_notes": "Discrepancies between Ghidra and IDA in function and string counts (0 vs 1 functions, 22 vs 229 strings) suggest packing or obfuscation; Ghidra found no imports while IDA found 2, aligning with Malcat's NoImportTable anomaly. Capa failed due to corrupt PE header, indicating high obfuscation.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "Packed",
      "why": "Malcat anomaly 'Packed' indicates the file is packed using an obfuscator, a neutral but common technique in malware to hinder analysis."
    },
    {
      "source": "packer_intake",
      "query_or_table": "packer_intake checks",
      "row_or_rule": "score=8",
      "why": "Packer_intake score of 8 based on high entropy in executable sections and raw vs virtual size mismatches, indicating packing or obfuscation."
    },
    {
      "source": "yara",
      "query_or_tab
… [5062 more chars]
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

#### `malcat` — ok=`True` why=`not_applicable:dotnet`

```json

```

#### `capa` — ok=`True` why=`packed_soft:packed:error:capa rc=13`

```json
{
  "error": "capa rc=13",
  "stderr": "ERROR    capa: Input file '/opt/samples/corpus/CTF 1 - Weeks   main.py:563\n         1-8/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f            \n         10ad013c9/Upack037.exe' is not a valid PE file: \"data at               \n         RVA can't be fetched. Corrupt header?\"                                 \n",
  "timeout_s": 900,
  "sample_size": 52224,
  "duration_s": 0.22,
  "engine": "capa"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 52224,
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
  "rule_count": 21,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 2212,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 6028,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 42,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "WinUpackv039finalByDwingc2005h1",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 24,
          "length": 84,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Upackv039finalDwing",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 240,
          "length": 23,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 160,
          "length": 23,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UpackV037Dwing",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 40,
          "length": 168,
          "xor_key": null
        },
        {
          "id": "$a2",
          "offset": 24,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "WinUpack_v039_final_By_Dwing_c2005_additional",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 24,
          "length": 321,
  
… [6728 more chars]
```

#### `floss` — ok=`True` why=`fail_open:floss rc=1:────────────────────────────────────────────────────╯    │
╰──────────────────────────────────────────────────────────────────────────────╯
TypeError: a bytes-like object is required, not 'NoneType'

`

```json
{
  "floss_ok": false,
  "static_only": true,
  "size_bytes": 52224,
  "size_exceeded_deobfuscate_limit": false,
  "fallback": "strings(1)",
  "fail_open": true,
  "reason": "floss rc=1:\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f    \u2502\n\u2570\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f\nTypeError: a bytes-like object is required, not 'NoneType'\n\n",
  "error": "floss rc=1:\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f    \u2502\n\u2570\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f\nTypeError: a bytes-like object is required, not 'NoneType'\n\n",
  "floss_profile": "full",
  "static_strings": [
    "MZKERNEL32.DLL",
    "LoadLibraryA",
    "GetProcAddress",
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">",
    "<assemblyIdentity",
    "name=\"Microsoft.Windows.Shell.calc\"",
    "processorArchitecture=\"x86\"",
    "version=\"5.1.0.0\"",
    "type=\"win32\"/>",
    "<description>Windows Shell</description>",
    "<dependency>",
    "<dependentAssembly>",
    "<assemblyIdentity",
    "type=\"win32\"",
    "name=\"Microsoft.Windows.Common-Controls\"",
    "version=\"6.0.0.0\"",
    "processorArchitecture=\"x86\"",
    "publicKeyToken=\"6595b64144ccf1df\"",
    "language=\"*\"",
    "</dependentAssembly>",
    "</dependency>",
    "</assembly>",
    "dDDDDDDDDDDDDD@",
    "fffffffffffff@",
    "opopopopowwpf@",
    "fffffffffffff@",
    "opopopopopopf@",
    "fffffffffffff@",
    "opopopopopopf@",
    "fffffffffffff@",
    "`wwwwwwwfffff@",
    "`wwwwwwwfffff@",
    "ffffffffffffffa",
    "fDDDDDD@offffff@n`",
    "p@offffff@n`",
    "@offffff@n",
    "|||ddcO87",
    "=||ccOM7",
    "`NfOM79|?4",
    "xrssssvvvv",
    "^zwurqqqqqsssssvvvv;",
    "^;LLZZzxxwtrqqrZ",
    "*4!XT?=,",
    "![kT@2P?.,",
    "cDfLMGN^J",
    "n?UKVWXC;",
    "FBA23>@S",
    "u&NU@[nAJ",
    "8cKFT/|,d",
    "#6I,;VRUw",
    "U2h\tS+J$w"
  ],
  "static_string_count": 52,
  "strings": [
    "MZKERNEL32.DLL",
    "LoadLibraryA",
    "GetProcAddress",
    "<?xml version=\"1.0\" en
… [1300 more chars]
```

#### `dotnet` — ok=`True` why=`packed_soft:packed:error:dnfile open failed: "data at RVA can't be fetched. Corrupt header?"`

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
  "il_excerpt": "",
  "error": "dnfile open failed: \"data at RVA can't be fetched. Corrupt header?\""
}
```

#### `r2_decomp` — ok=`True` why=`ok`

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
  "disassembly": {
    "0x01001018": "\u250c 64: entry0 ();\n\u2502           0x01001018      beb0110001     mov esi, 0x10011b0\n\u2502           0x0100101d      ad             lodsd eax, dword [esi]\n\u2502           0x0100101e      50             push eax\n\u2502           0x0100101f      ff7634         push dword [esi + 0x34]\n\u2502       \u250c\u2500< 0x01001022      eb7c           jmp 0x10010a0\n..\n\u2502       \u2502   ; CODE XREF from entry0 @ 0x1001022(x)\n\u2502       \u2514\u2500> 0x010010a0      ff7638         push dword [esi + 0x38]\n\u2502       \u2502   0x010010a3      ad             lodsd eax, dword [esi]\n\u2502       \u2502   0x010010a4      50             push eax\n\u2502       \u2502   0x010010a5      8b3e           mov edi, dword [esi]\n\u2502       \u2502   0x010010a7      bef0400301     mov esi, 0x10340f0\n\u2502       \u2502   0x010010ac      6a27           push 0x27                   ; '\\'' ; 39\n\u2502       \u2502   0x010010ae      59             pop ecx\n\u2502       \u2502   0x010010af      f3a5           rep movsd dword es:[edi], dword [esi]\n\u2502       \u2502   0x010010b1      ff7604         push dword [esi + 4]\n\u2502       \u2502   0x010010b4      83c8ff         or eax, 0xffffffff          ; -1\n\u2502       \u2502   0x010010b7      8bdf           mov ebx, edi\n\u2502       \u2502   0x010010b9      ab             stosd dword es:[edi], eax\n\u2502      \u250c\u2500\u2500< 0x010010ba      eb1c           jmp 0x10010d8\n..\n\u2502  \u2502\u2502\u2502\u2502\u2502\u2502   ; CODE XREF from entry0 @ 0x10010ba(x)\n\u2502  \u2502\u2502\u2502\u2502\u2514\u2500\u2500> 0x010010d8      40             inc eax\n\u2502  \u2502\u2502\u2502\u2502 \u2502   0x010010d9      ab             stosd dword es:[edi], eax\n\u2502  \u2502\u2502\u2502\u2502 \u2502   0x010010da      40             inc eax\n\u2502  \u2502\u2502\u2502\u2502 \u2514\u2500> 0x010010db      b104           mov cl, 4\n\u2502  \u2502\u2502\u2502\u2502     0x010010dd      f3ab           rep stosd dword es:[edi], eax\n\u2502  \u2502\u2502\u2502\u2502     0x010010df      c1e00a         shl eax, 0xa\n\u2502  \u2502\u2502\u2502\u2502     0x010010e2      b51c           mov ch, 0x1c                ; 28\n\u2502  \u2502\u2502\u2502\u2502     0x010010e4      f3ab           rep stosd dword es:[edi], eax\n\u2502  \u2502\u2502\u2502\u2502     0x010010e6      8b7e0c         mov edi, dword [esi + 0xc]\n\u2502  \u2502\u2502\u2502\u2502     0x010010e9      57             push edi\n\u2502  \u2502\u2502\u2502\u2502     0x010010ea      51             push ecx\n\u2514  \u2502\u2502\u2502\u2502 \u250c\u2500< 0x010010eb      e9fbb70200     jmp loc.0102c8eb",
    "0x0102c8eb": "; CODE XREF from entry0 @ 0x10010eb(x)\n\u251c 30521: loc.0102c8eb ();\n\u2502 0x0102c8eb      58             pop eax\n\u2502 0x0102c8ec      8d548358       lea edx, [ebx + eax*4 + 0x58]\n\u2502 0x0102c8f0      ff16           call dword [esi]\n\u2502 0x0102c8f2      724f           jb 0x102c943\n\u2502 0x0102c8f4      04fd           add al, 0xfd                          ; 253\n\u2502 0x0102c8f6      1ad2           sbb dl, dl\n\u2502 0x0102c8f8      22c2           and al, dl\n\u2502 0x0102c8fa      3c07           cmp al, 7                             ; 7\n\u2502 0x0102c8fc      73f6           jae 0x102c8f4\n\u2502 0x0102c8fe      50             push eax\n\
… [8420 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 00000010 .@....................9..........P...."
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000010 .@....................9..........P....\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`not_applicable:dotnet`

```json

```

#### `frida_probe` — ok=`True` why=`ok`

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
    "exists": true,
    "hook_candidates": []
  }
}
```

#### `frida_trace` — ok=`True` why=`not_applicable:dotnet`

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
    "YARA: 21 rules matched including WinUpackv039finalByDwing, UpackV037Dwing, Upack_V037_V039_Dwing, Upack_v039_final - def",
    "IDA imports: Only KERNEL32!LoadLibraryA (0x1001828) and KERNEL32!GetProcAddress (0x100182C) - classic packer stub with d",
    "capa error: 'data at RVA can't be fetched. Corrupt header?' - PE structure intentionally corrupted by Upack packer",
    "Ghidra memory_blocks: All 3 code segments (PS______, seg003, M_____) have perm=7 (RWX) - indicates self-modifying/unpack",
    "YARA: HasOverlay, HasModified_DOS_Message - packer structural anomalies"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This sample is a packed executable using Upack v0.37 packer that masquerades as Windows Calculator (CALC.EXE) from Microsoft Corporation. The PE header is intentionally corrupted (capa reports 'data at RVA can't be fetched. Corrupt header?'), characteristic of Upack-packed files. Only two imports ex",
  "key_evidence": [
    "YARA: 21 rules matched including WinUpackv039finalByDwing, UpackV037Dwing, Upack_V037_V039_Dwing, Upack_v039_final - definitive Upack packer identification",
    "IDA imports: Only KERNEL32!LoadLibraryA (0x1001828) and KERNEL32!GetProcAddress (0x100182C) - classic packer stub with dynamic API resolution",
    "capa error: 'data at RVA can't be fetched. Corrupt header?' - PE structure intentionally corrupted by Upack packer",
    "Ghidra memory_blocks: All 3 code segments (PS______, seg003, M_____) have perm=7 (RWX) - indicates self-modifying/unpacking code",
    "YARA: HasOverlay, HasModified_DOS_Message - packer structural anomalies",
    "YARA: domain rule matched at offset 0, IPv4 at offset 2212, IPv6 at offset 6028 - embedded network indicators",
    "YARA: contains_base64 matched at offset 42 - encoded content in payload",
    "Ghidra strings: Version info masquerades as 'Windows Calculator application file' by 'Microsoft Corporation' v5.1.2600.0, OriginalFilename='CALC.EXE' - brand spoofing",
    "FLOSS failure: 'TypeError: a bytes-like object is required, not NoneType' - PE corruption prevents stack string extraction",
    "File labeled as 'dotnet' type but packed with Upack native packer - likely .NET payload wrapped in native packer shell"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 21,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "p
… [9828 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
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
    "file_name": "Upack037.exe
… [44561 more chars]
```

- **capa_analyze** ok=`False` checklist=`True` — Required checklist tool (capa)
  - error: `capa rc=13`

```json
{
  "error": "capa rc=13",
  "stderr": "ERROR    capa: Input file '/opt/samples/corpus/CTF 1 - Weeks   main.py:563\n         1-8/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f            \n         10ad013c9/Upack037.exe' is not a valid PE file: \"data at               \n         RVA can't be fetched. Corrupt header?\"                                 \n",
  "timeout_s": 900,
  "samp
… [59 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 52224,
  "duration_s": 0.03,
  "import_count": 0,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`False` checklist=`True` — Required checklist tool (floss)
  - error: `floss rc=1:────────────────────────────────────────────────────╯    │
╰──────────────────────────────────────────────────────────────────────────────╯
TypeError: a bytes-like object is required, not 'NoneType'

`

```json
{
  "floss_ok": false,
  "static_only": true,
  "size_bytes": 52224,
  "size_exceeded_deobfuscate_limit": false,
  "fallback": "strings(1)",
  "fail_open": true,
  "reason": "floss rc=1:\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u25
… [4400 more chars]
```

- **dotnet_analyze** ok=`False` checklist=`True` — Required checklist tool (dotnet)
  - error: `dnfile open failed: "data at RVA can't be fetched. Corrupt header?"`

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
  "il_excerpt": "",
  "error": "dnfile open failed: \"data at RVA c
… [37 more chars]
```

- **r2_decompile** ok=`True` checklist=`True` — Required checklist tool (r2_decomp)

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
  "disassembly": {
    "0x01001018": "\u250c 64: entry0 ();\n\u2502           0x01001018      beb0110001     mov esi, 0x10011b0\n\u2502           0x0100101d      ad             lodsd eax, dword [esi]\n\u2502           0x0100101e      50        
… [11520 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTeste
… [11 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 00000010 .@....................9..........P...."
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000010 .@....................9..........P....\n",
  "xorsearch_stderr":
… [34 more chars]
```

- **frida_static_probe** ok=`True` checklist=`True` — Required checklist tool (frida_probe)

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
    "exists": true,
    "hook_candidates": []
  }
}
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 7.42,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.03,
 
… [101 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "packed",
  "name": null,
  "score": 8
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
  "audit_path": "/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

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
  "session_id": "ghidra-dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
  "audit_path": "/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/audit.jsonl"
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
      "content": " Microsoft Corporation. All rights reserved.",
      "address": "16910939",
      "length": "90"
    },
    {
      "content": "Windows Calculator application file",
      "address": "16910685",
      "length": "72"
    },
    {
      "content": "5.1.2600.0 (xpclient.010817-1148)",
      "address":
… [2167 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
  "audit_path": "/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/audit.jsonl"
}
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
      "name": "start",
      "address": "16781336",
      "size": "216"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
  "audit_path": "/opt/samples/logs/36137a22c973fdb6a5029319d8f
… [52 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "module",
    "name",
    "address"
  ],
  "rows": [
    {
      "module": "KERNEL32",
      "name": "LoadLibraryA",
      "address": "16781800"
    },
    {
      "module": "KERNEL32",
      "name": "GetProcAddress",
      "address": "16781804"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-36137a22c973
… [169 more chars]
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
      "content": "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n<assemblyIdentity\r\n    name=\"Microsoft.Windows.Shell.calc\"\r\n    processorArchitecture=\"x86\"\r\n    version=\"5.1.0.0\"\r\n    type=\"win32\"/>\r\
… [3749 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "start_ea",
    "end_ea",
    "name",
    "class",
    "perm"
  ],
  "rows": [
    {
      "start_ea": "16781312",
      "end_ea": "16781800",
      "name": "PS_____",
      "class": "CODE",
      "perm": "7"
    },
    {
      "start_ea": "16781800",
      "end_ea": "16781808",
      "name": ".idata",
      "class": "XTRN",
      "perm": "7"
    },
    {
      "start_ea": "16
… [677 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "start_ea",
    "end_ea",
    "name",
    "class",
    "perm",
    "bitness",
    "size",
    "is_read",
    "is_write",
    "is_exec"
  ],
  "rows": [
    {
      "start_ea": "16781312",
      "end_ea": "16908287",
      "name": "PS______",
      "class": "CODE",
      "perm": "7",
      "bitness": "0",
      "size": "126976",
      "is_read": "1",
      "is_write": "1",
    
… [1069 more chars]
```

- **capa_analyze** ok=`False` checklist=`False` — langgraph tool call
  - error: `capa rc=13`

```json
{
  "error": "capa rc=13",
  "stderr": "ERROR    capa: Input file '/opt/samples/corpus/CTF 1 - Weeks   main.py:563\n         1-8/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f            \n         10ad013c9/Upack037.exe' is not a valid PE file: \"data at               \n         RVA can't be fetched. Corrupt header?\"                                 \n",
  "timeout_s": 900,
  "samp
… [59 more chars]
```

- **floss_extract** ok=`False` checklist=`False` — langgraph tool call
  - error: `floss rc=1:────────────────────────────────────────────────────╯    │
╰──────────────────────────────────────────────────────────────────────────────╯
TypeError: a bytes-like object is required, not 'NoneType'

`

```json
{
  "floss_ok": false,
  "static_only": true,
  "size_bytes": 52224,
  "size_exceeded_deobfuscate_limit": false,
  "fallback": "strings(1)",
  "fail_open": true,
  "reason": "floss rc=1:\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u25
… [4400 more chars]
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
      "content": "MZKERNEL32.DLL",
      "address": "16781312",
      "length": "15"
    },
    {
      "content": "LoadLibraryA",
      "address": "16781354",
      "length": "13"
    },
    {
      "content": "GetProcAddress",
      "address": "16781504",
      "length": "15"
    },
    {
      "content": "<?xml v
… [3707 more chars]
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
  "session_id": "ghidra-dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
  "audit_path": "/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/audit.jsonl"
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
      "content": "CALC.EXE",
      "address": "16911069",
      "length": "19"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
  "audit_path": "/opt/samples/logs/36
… [77 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9.json"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "from_ea",
    "to_ea",
    "from_func",
    "type",
    "is_code"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9",
  "audit_path": "/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/audit.jsonl"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/dotnet-36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9.json"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/deep_dive/01-tools-raw.json` exists=`True` bytes=`81640` mtime=`2026-08-09T23:43:35.291843+00:00`
  - sha256: `baeea5521dd6d2ca32327e92ea6579e0fee1fa421ec8132c4f735c6dd2236fe6`
- **sql_evidence:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/deep_dive/05-deep-dive.json` exists=`True` bytes=`4884` mtime=`2026-08-09T23:45:04.411465+00:00`
  - sha256: `2a2808791780be74985d18b07144a8bbeef161056638bd50bd0eaf46aa5ad385`

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
  "summary": "This sample is a packed executable using Upack v0.37 packer that masquerades as Windows Calculator (CALC.EXE) from Microsoft Corporation. The PE header is intentionally corrupted (capa reports 'data at RVA can't be fetched. Corrupt header?'), characteristic of Upack-packed files. Only two imports exist (LoadLibraryA and GetProcAddress), which is the classic packer stub pattern for dynamic API resolution to evade static analysis. All memory segments are marked RWX (read/write/execute), indicating self-modifying code behavior. The file contains embedded IP addresses (IPv4/IPv6), domain patterns, and base64-encoded content detected by YARA. FLOSS failed to extract stack stri
… [4084 more chars]
```

- **agentic:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`254949` mtime=`2026-08-09T23:45:04.411465+00:00`
  - sha256: `e9305a6e3ce25b59e84820bb313448020f643a166ef0dfcb96db100b32d55609`

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

- **rule_yar:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/rule.yar` exists=`True` bytes=`1206` mtime=`2026-08-09T23:45:07.511475+00:00`
  - sha256: `8cf08d54116265642c4d4403d76aa8e5ea1f677e4850d71be0fd8a63f86d03c9`

#### excerpt

```
// yara_gen_v2.py — 2026-08-09T23:45:07.511240+00:00
rule CADRE_v2_upack_36137a22c973 {
    meta:
        description = "RevAI v2 auto rule for Upack"
        sha256 = "36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9"
        family = "upack"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "MZKERNEL32.DLL" ascii wide
        $s1 = "LoadLibraryA" ascii wide
        $s2 = "GetProcAddress" ascii wide
        $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" ascii wide
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" ascii wide
        $s5 = "<assemblyIdentity" ascii wide
        $s6 = "name
… [404 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/REPORT-MASTER-v2.md` exists=`True` bytes=`17311` mtime=`2026-08-09T23:47:54.478644+00:00`
  - sha256: `b2779cb64e958a59176aebc8bc0676bf6560a5e8a79739ceff9d6f726d0cad63`
- **REPORT_MASTER_v3:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/REPORT-MASTER-v3.md` exists=`True` bytes=`44741` mtime=`2026-08-09T23:54:55.642288+00:00`
  - sha256: `951dc79fd7a31e2bc807519967a67da6eed5a4673fd8ef2d4514767812ea6877`
- **REPORT_v2:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/REPORT-v2.md` exists=`True` bytes=`17311` mtime=`2026-08-09T23:47:54.478644+00:00`
  - sha256: `b2779cb64e958a59176aebc8bc0676bf6560a5e8a79739ceff9d6f726d0cad63`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`47957` mtime=`2026-08-09T23:49:24.657566+00:00`
  - sha256: `d67839316f2d19e51cfb781fa8b1cbdbe47f09cefacdfe2bb33d5d83c1938e52`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`40615` mtime=`2026-08-09T23:56:22.873365+00:00`
  - sha256: `142a5ce03742aacb93653e2b1a3bbefa10874bdbc2ed290314164829333e2466`
- **report_v2_json:** `/opt/samples/logs/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/report-v2.json` exists=`True` bytes=`20510` mtime=`2026-08-09T23:49:24.661566+00:00`
  - sha256: `a35afe8e8288e644d60c5e602fb3246d605dc2bcb168849e87bc2f265fb7503c`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 23:47:54 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: WinUpackv039finalByDwingc2005h1, Upackv039finalDwing, UpackV037Dwing, IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message, WinUpack_v039_final_By_Dwing_c2005_additional). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Upack
- **Honesty:** the publish narrative below is **preserved unedited** so analy
… [16402 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 23:54:55 UTC

# RE Report — 36137a22c973
_Generated 2026-08-09T23:54:55.640044+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=214c | cross_refs=True | llm_ok=True | runtime=43.35s -->

**Executive Summary**

The sample with SHA256 `36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9` is assessed as **suspicious** with indicators pointing towards malicious intent, likely associated with the **Upack** family, a known packer for obfuscating malware. Confidence in this assessment is high, supported by a deep analysis with a confidence score of 90. The sample exhibits obfuscation tec
… [43818 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
