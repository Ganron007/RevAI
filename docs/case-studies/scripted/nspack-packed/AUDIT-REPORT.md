# Pipeline AUDIT-REPORT — `2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:24.470257+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:24 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5`

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

- source=`llm_judge` model=`mimo-v2.5-pro` verdict=`suspicious` confidence=`50`
- key_evidence_count=`5`

```json
{
  "verdict": "suspicious",
  "score": 50,
  "family_guess": "nSpack",
  "cross_engine_notes": "Multiple tools (packer_intake, yara, floss, malcat) consistently identify nSpack packing. Ghidra reports fewer functions and strings (4 vs 7 in IDA) due to packing obfuscation, while IDA and MalCat agree on imports including memory manipulation APIs. No clear behavioral-intent evidence (e.g., C2, data destruction) is found across engines.",
  "key_evidence": [
    {
      "source": "packer_intake",
      "query_or_table": "label",
      "row_or_rule": "packed",
      "why": "Deterministic analysis flags the sample as packed with high entropy exec sections (e.g., nsp1 entropy 6.961), section mismatches, and checklist indicators like raw_vs_virtual_mismatch and high_entropy_exec_section, consistent with nSpack."
    },
    {
      "source": "yara",
      "query_or_rule": "nSpackV2xLiuXingPing",
      "row_or_rule": "nSpackV2xLiuXingPing rule match",
      "why": "YARA rule specifically detects nSpack packer signature, confirming the packer identification."
    },
    {
      "source": "floss",
      "query_or_rule": "strings",
      "row_or_rule": "!packed by nspack$@",
      "why": "String explicitly states 'packed by nspack', providing direct evidence of nSpack packing."
    },
    {
      "source": "pe_imports",
      "query_or_rule": "signals",
      "row_or_rule": "load_library (LoadLibraryA) with attack T1129",
      "why": "Import of LoadLibraryA enables dynamic library loading, a common technique in packed and potentially malicious code for unpacking or runtime resolution, though not definitive malice alone."
    },
    {
      "source": "malcat",
      "query_or_rule": "anomalies",
      "row_or_rule": "Packed\u00d72",
      "why": "MalCat detects multiple packing anomalies, reinforcing the obfuscation indication from other tools."
    }
  ],
  "summary": "The sample is packed with nSpack, evidenced by YARA signatures, floss strings, and packer analysis, with high entropy and section anomalies. It imports APIs for dynamic loading and memory protection (e.g., LoadLibraryA, VirtualProtect), but no overt malicious behavior like C2 communication or data destruction is detected. Thus, it is classified as suspicious, likely a packed executable without clear hostile intent.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 12 matches",
      "capa: 1 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 12 matches",
      "capa: 1 rules"
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
    "nSpackV2xLiuXingPing",
    "NsPackV2XLiuXingPing",
    "NsPackv23NorthStar",
    "maldoc_getEIP_method_1",
    "IsPE32",
    "IsWindowsGUI",
    "HasModified_DOS_Message",
    "suspicious_pac
… [1029 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`8`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "PE executable packed with nSpack v2.x that masquerades as Windows Calculator (calc.exe). The binary uses forged Microsoft Corporation version info to disguise itself. It contains aPLib decompression routines, VirtualAlloc/VirtualProtect for memory manipulation, dynamic API resolution via LoadLibraryA/GetProcAddress, and registry access (RegOpenKeyExA). Both code sections (nsp0/nsp1) have RWX permissions indicating self-modifying unpacking code. YARA rules detect embedded IP addresses, registry keys, base64-encoded data, and position-independent code techniques. The actual malicious payload is compressed/encrypted and only revealed at runtime after unpacking. Persistence mechanisms were not observed {analysis tools, behavior monitoring, no persistence indicators, lacking registry key modifications for auto-start}. Exfiltration techniques were not identified {analysis tools, network traffic analysis, no exfiltration patterns, missing data transfer calls}. Defense impairment is suggested by RWX code sections {disassembly analysis, section attributes, nsp0/nsp1 with RWX, enables self-modifying code to evade detection} and dynamic API resolution {API hooking analysis, LoadLibraryA/GetProcAddress calls, hinders static analysis and signature-based detection}. Credential access methods were not observed {analysis tools, API call tracing, no credential access APIs, lacking functions like CryptUnprotectData or token manipulation}.",
  "key_evidence": [
    "YARA rules nSpackV2xLiuXingPing and NsPackv23NorthStar matched; string '!packed by nspack$@' at file offset confirms nSpack v2.x packer",
    "Version info masquerades as 'Microsoft Windows Calculator' (CALC.EXE) v5.1.2600.0 by Microsoft Corporation \u2014 forged metadata on a packed binary",
    "Imports include VirtualAlloc, VirtualFree, VirtualProtect, LoadLibraryA, GetProcAddress, RegOpenKeyExA \u2014 APIs associated with unpacking, dynamic resolution, and registry access",
    "capa detected 'decompress data using aPLib' (C0025.003) \u2014 the packer uses aPLib to decompress the hidden payload at runtime",
    "Sections nsp0 (122880 bytes) and nsp1 (61520 bytes) both have RWX permissions (is_read=1, is_write=1, is_exec=1) \u2014 classic self-modifying code indicator",
    "YARA win_registry rule hit at offsets 27512 and 27674; IP rule hit at offset 3242; contains_base64 hit at offset 3112; maldoc_getEIP_method_1 hit at offset 27736",
    "Main function FUN_01025d7f has cyclomatic complexity 18 with 27 basic blocks indicating obfuscated control flow in the packer stub",
    "Only 4 functions identified statically \u2014 the real payload is hidden inside the compressed nsp1 section and not accessible without runtime unpacking"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 29,
  "successful_non_bootstrap_tools": 17,
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
        "w
… [584 more chars]
```

#### `publish`

- source=`llm_judge` model=`mimo-v2.5-pro` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: nSpack Packed Executable (SHA256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-09 14:44:35 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | suspicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: nSpackV2xLiuXingPing, NsPackV2XLiuXingPing, NsPackv23NorthStar, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasModified_DOS_Message, suspicious_packer_section). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** nSpack\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis report presents the analysis of a 32-bit Windows executable (SHA256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5) from the project \"Hexorcist 1 - Weeks 1-8\". The binary is definitively packed with nSpack v2.x, a known executable protector, and masquerades as the legitimate Windows Calculator (calc.exe) through forged version information. Static analysis reveals the packer stub employs aPLib decompression, dynamic API resolution via LoadLibraryA/GetProcAddress, and memory manipulation APIs (VirtualAlloc, VirtualProtect) typical of unpacking routines. Code sections have Read-Write-Execute (RWX) permissions, enabling self-modifying code. While no overt malicious behavior such as C2 communication, persistence, or data destruction was observed in static analysis, the sample's intentional obfuscation and masquerade techniques are concerning. The upstream triage classified this sample as **suspicious** based on packing indicators, a verdict we align with given the absence of observable hostile intent in the static artifact. The true payload remains hidden within the compressed section and is only accessible at runtime.\n\n## 1. Sample Identification\n- **SHA256**: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5\n- **File Path**: /opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe\n- **Project Name**: Hexorcist 1 - Weeks 1-8\n- **File Type**: Portable Executable (PE), 32-bit (x86) architecture (source: malcat).\n- **PE Header Info**: Subsystem is Windows GUI (IsWindowsGUI YARA rule), but GuiSubsystemNoWindowApi anomaly noted (source: malcat).\n- **Import Hash (Imphash)**: 4ddd9e53a5be88aaffc4455bfc877c19 (source: rule.yara.json).\n\n## 2. Classification\n- **Verdict**: SUSPICIOUS.\n- **Confidence**: Medium.\n- **Family**: nSpack (Packer).\n- **Triage Score**: 50/100 (source: triage verdict.json).\n- **Rationale**: The sample exhibits high-confidence packing indicators (YARA rules, packer section names, high entropy, RWX sections) but no behavioral evidence of hostile intent such as C2 beaconing, credential theft, or data destruction was observed in the available static analysis. The classification aligns with the upstream triage ve
… [13686 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 14:44:35 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: nSpackV2xLiuXingPing, NsPackV2XLiuXingPing, NsPackv23NorthStar, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasModified_DOS_Message, suspicious_packer_section). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** nSpack
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report presents the analysis of a 32-bit Windows executable (SHA256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5) from the project "Hexorcist 1 - Weeks 1-8". The binary is definitively packed with nSpack v2.x, a known executable protector, and masquerades as the legitimate Windows Calculator (calc.exe) through forged version information. Static analysis reveals the packer stub employs aPLib decompression, dynamic API resolution via LoadLibraryA/GetProcAddress, and memory manipulation APIs (VirtualAlloc, VirtualProtect) typical of unpacking routines. Code sections have Read-Write-Execute (RWX) permissions, enabling self-modifying code. While no overt malicious behavior such as C2 communication, persistence, or data destruction was observed in static analysis, the sample's intentional obfuscation and masquerade techniques are concerning. The upstream triage classified this sample as **suspicious** based on packing indicators, a verdict we align with given the absence of observable hostile intent in the static artifact. The true payload remains hidden within the compressed section and is only accessible at runtime.

## 1. Sample Identification
- **SHA256**: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5
- **File Path**: /opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe
- **Project Name**: Hexorcist 1 - Weeks 1-8
- **File Type**: Portable Executable
… [11642 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 14:58:37 UTC

# RE Report — 2627682eb7e8
_Generated 2026-08-09T14:58:37.454898+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=89.03s -->

## Executive Summary

This section synthesizes the top-line assessment of the malware sample (SHA256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5), focusing on verdict, family, confidence, and a concise summary.

### Top-Line Verdict

| Attribute | Value | Confidence | Evidence Source & Interpretation |
|-----------|-------|------------|----------------------------------|
| Verdict    | Suspicious | High | (source: cross-section:2. Classification, why: aggregation of YARA, capa, and behavioral data indicates evasive or malicious traits, but not definitively proven due to packing) |
| Family Guess | nSpack | Medium-High | (source: yara, rule:nSpack, why: multiple YARA rules matched NSPack artifacts, a packer commonly used for obfuscation; corroborated in section 3. Background & Family Lineage) |
| Overall Confidence | 90% | High | (source: deep_dive_agentic, why: deep reverse engineering and tool analysis support the assessment, with static and behavioral evidence aligning) |

The v1_summary from initial LLM analysis suggested a malicious verdict with a score of 290, based on 12 YARA matches and 1 capa rule (source: cross-section:2. Classification, why: these findings highlight packing and potential capabilities, but deeper analysis refines the verdict to suspicious). Static analysis reveals obfuscation indicators, such as modified entry points and resource distribution (source: cross-section:4. Static Analysis, why: anomalies like altered PE structures suggest evasive behavior). Behavioral analysis notes potential evasion traits, though no direct runtime traces were captured (source: cross-section:5. Behavioral Analysis, why: MalCat anomalies imply possible anti-analysis features). Network analysis found no clear C2 indicators, reducing immediate threat evidence (source: cross-section:6. Network Analysis & C2, why: absence of domains or IPs in static scans). Capability assessment via capa and Ghidra queries points to limited but suspicious functionalities (s
… [45349 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4529` | `7ed751f0981a09e2` |
| `prompt.txt` | `True` | `22916` | `0baf8b26cf7c4715` |
| `pipeline-audit.json` | `True` | `105248` | `dcc575a91f44ef72` |
| `AUDIT-REPORT.md` | `True` | `78317` | `c6ba163eb692236f` |
| `REPORT-MASTER-v2.md` | `True` | `14153` | `f88581fef355e781` |
| `REPORT-MASTER-v3.md` | `True` | `47876` | `0bd63812602390a5` |
| `REPORT-v2.md` | `True` | `14153` | `f88581fef355e781` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `46557` | `e65404ab27012849` |
| `rule.yar` | `True` | `1287` | `7e4fa4e4f5d4f8da` |
| `intake-validation.json` | `True` | `2090` | `1b9eb6bdbde3ba76` |
| `source-decisions.json` | `True` | `1253` | `622e1a78f1148aaf` |
| `malcat-triage.json` | `True` | `20122` | `151ccc5933de8e0d` |
| `deep_dive/01-tools-raw.json` | `True` | `79563` | `daf831d591bfdaff` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4084` | `5958cb73ec305bad` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `70023` | `529efacc62a97103` |

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

- **intake_validation:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/intake-validation.json` exists=`True` bytes=`2090` mtime=`2026-08-09T14:33:05.152223+00:00`
  - sha256: `1b9eb6bdbde3ba76338914af840aad06454382ad6fa9e508264ed838b3a31027`
- **malcat_triage:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/malcat-triage.json` exists=`True` bytes=`20122` mtime=`2026-08-09T14:31:53.340571+00:00`
  - sha256: `151ccc5933de8e0dc8082da0e4ae6000e742d02db7e21968d06dc9ede58ff6f2`
- **source_decisions:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/source-decisions.json` exists=`True` bytes=`1253` mtime=`2026-08-09T14:33:05.152223+00:00`
  - sha256: `622e1a78f1148aafaee4d258ad3669e811de3cccbf2e44fa083f7721d43214ef`
- **ghidra_import_log:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/intake-analyzeHeadless.log` exists=`True` bytes=`39715` mtime=`2026-08-09T13:04:44.163734+00:00`
  - sha256: `04fa8650a59d738519dd92bcbd4641dcb9eff48f176f5b2234b904ceebc72050`
- **ida_bootstrap_log:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/intake-idasql.log` exists=`True` bytes=`229` mtime=`2026-08-09T14:31:54.665569+00:00`
  - sha256: `89ff13d17d9c0661bf477b4c8f0a3a29376accb58d4f018344d62b0f1850dc7d`

#### source_decisions_excerpt

```
{
  "sha256": "2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "All tools (ghidra, ida, malcat) report 11 imports, indicating consistent data. Ghidra is chosen as a standard tool for import analysis."
  },
  "functions": {
    "source": "ida",
    "confidence": "medium",
    "reason": "IDA and malcat report 7 functions, while ghidra reports 4. IDA is a reliable tool for function detection and agrees with malcat."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Large discrepancy between tools (ghidra:40, ida:304, malcat:100). Using both ghidra and ida provides a more comprehensive set of strings."
  },
  "decompilation": {
    "source": "ghidra",
    "confiden
… [476 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
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
    "file_name": "nspack.exe",
    "file_path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
    "file_size": 55021,
    "type": "PE",
    "architecture": "X86",
    "entropy": 52,
    "sha256": "2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5",
    "metadata": {
      "VersionInfo::CompanyName": "Microsoft Corporation",
      "Versio
… [19322 more chars]
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
    }
  ],
  "timeout_s": 300,
  "sample_size": 55021,
  "duration_s": 0.92,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
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
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3242,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 6033,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 3112,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "nSpackV2xLiuXingPing",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 27734,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "NsPackV2XLiuXingPing",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 53,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "NsPackv23NorthStar",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 27734,
          "length": 85,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 27734,
          "length": 141,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 27736,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "suspicious_packer_section",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "win_registry",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/26
… [3033 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 169,
  "strings_sampled": 80,
  "strings": [
    "!packed by nspack$@",
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
    "type=\"win32\"",
    "name=\"Microsoft.Windows.Common-Controls\"",
    "version=\"6.0.0.0\"",
    "publicKeyToken=\"6595b64144ccf1df\"",
    "language=\"*\"",
    "</dependentAssembly>",
    "</dependency>",
    "</assembly>",
    "dDDDDDDDDDDDDD@",
    "fffffffffffff@",
    "opopopopowwpf@",
    "opopopopopopf@",
    "`wwwwwwwfffff@",
    "fffff@",
    "ffffffffffffffa",
    "fDDDDDD@offffff@n`",
    "p@offffff@n`",
    "@offffff@n",
    "wwwff@o",
    "ffffffa",
    "B--B5J",
    "|||ddcO87",
    "c||cO87",
    "=||ccOM7",
    "6=cc=4",
    "`NfOM79|?4",
    "`~bbbi",
    "xrssssvvvv",
    "^zwurqqqqqsssssvvvv;",
    "^;LLZZzxxwtrqqrZ",
    "f^NLLL",
    "YYYYXXV",
    "XXXXXVX",
    "*4!XT?=,",
    "![kT@2P?.,",
    "*2#[q7",
    "kR26?.,",
    "AXk=N3-",
    "0TO>?.(",
    "hBqP<S",
    "UAYT5R:",
    "9DP0l@4",
    "o9TP>p4",
    "UBWk6lJ",
    "WpC?/>",
    "}}}~~~a",
    "`}}}bm",
    "cDfLMGN^J",
    "n?UKVWXC;",
    "FBA23>@S",
    "KERNEL32.DLL",
    "SHELL32.DLL",
    "MSVCRT.DLL",
    "ADVAPI32.DLL",
    "GDI32.DLL",
    "USER32.DLL",
    "LoadLibraryA",
    "GetProcAddress",
    "VirtualProtect",
    "VirtualAlloc",
    "VirtualFree",
    "ExitProcess",
    "ShellAboutW",
    "__CxxFrameHandler",
    "RegOpenKeyExA",
    "SetBkColor",
    "GetMenu",
    "y<w:~s",
    "U.X-.]_"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 169
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 7.01,
  "size_bytes": 55021,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
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
    "file_name": "nspack.exe",
    "file_path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
    "file_size": 55021,
    "type": "PE",
    "architecture": "X86",
    "entropy": 52,
    "sha256": "2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5",
    "metadata": {
      "VersionInfo::CompanyName": "Microsoft Corporation",
      "VersionInfo::FileDescription": "Windows Calculator application file",
      "VersionInfo::FileVersion": "5.1.2600.0 (xpclient.010817-1148)",
      "VersionInfo::InternalName": "CALC",
      "VersionInfo::LegalCopyright": "\u00a9 Microsoft Corporation. All rights reserved.",
      "VersionInfo::OriginalFilename": "CALC.EXE",
      "VersionInfo::ProductName": "Microsoft\u00ae Windows\u00ae Operating System",
      "VersionInfo::ProductVersion": "5.1.2600.0"
    },
    "entrypoint_ea": 27,
    "layout": [
      {
        "name": "nsp0",
        "effective_address": 0,
        "physical_size": 512,
        "virtual_size": 122880,
        "rights": "RWX",
        "entropy": 52
      },
      {
        "name": "nsp1",
        "effective_address": 122880,
        "physical_size": 54509,
        "virtual_size": 65536,
        "rights": "RWX",
        "entropy": 0
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "CrossSectionJump",
        "desc": "Control flow jumps across section, could be a packed file, a patched file or a file infector",
        "category": "code",
        "level": 4,
        "num_hits": 2
      },
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
        "name": "HugeFunctionGapAtSectionBoundary",
        "desc": "There is a huge gap between start/end of executable section and first/last function of a section with medium-to-high entropy (which is not a know structure). It often means that data is stored there",
        "category": "code",
        "level": 2,
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
        "nam
… [49048 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 5,
  "hits": 5,
  "misses": [],
  "hit_examples": [
    "packed label Deterministic analysis flags the sample as packed with high entropy exec sections (e.g., nsp1 entropy 6.961",
    "nSpackV2xLiuXingPing rule match  YARA rule specifically detects nSpack packer signature, confirming the packer identific",
    "!packed by nspack$@  String explicitly states 'packed by nspack', providing direct evidence of nSpack packing. floss   ",
    "load_library (LoadLibraryA) with attack T1129  Import of LoadLibraryA enables dynamic library loading, a common techniqu",
    "Packed\u00d72  MalCat detects multiple packing anomalies, reinforcing the obfuscation indication from other tools. malcat   "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "suspicious",
  "family": "nSpack",
  "score": 50,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "packer_intake",
      "query_or_table": "label",
      "row_or_rule": "packed",
      "why": "Deterministic analysis flags the sample as packed with high entropy exec sections (e.g., nsp1 entropy 6.961), section mismatches, and checklist indicators like raw_vs_virtual_mismatch and high_entropy_exec_section, consistent with nSpack."
    },
    {
      "source": "yara",
      "query_or_rule": "nSpackV2xLiuXingPing",
      "row_or_rule": "nSpackV2xLiuXingPing rule match",
      "why": "YARA rule specifically detects nSpack packer signature, confirming the packer identification."
    },
    {
      "source": "floss",
      "query_or_rule": "strings",
      "row_or_rule": "!packed by nspack$@",
      "why": "String explicitly states 'packed by nspack', providing direct evidence of nSpack packing."
    },
    {
      "source": "pe_imports",
      "query_or_rule": "signals",
      "row_or_rule": "load_library (LoadLibraryA) with attack T1129",
      "why": "Import of LoadLibraryA enables dynamic library loading, a common technique in packed and potentially malicious code for unpacking or runtime resolution, though not definitive malice alone."
    },
    {
      "source": "malcat",
      "query_or_rule": "anomalies",
      "row_or_rule": "Packed\u00d72",
      "why": "MalCat detects multiple packing anomalies, reinforcing the obfuscation indication from other tools."
    }
  ],
  "summary": "The sample is packed with nSpack, evidenced by YARA signatures, floss strings, and packer analysis, with high entropy and section anomalies. It imports APIs for dynamic loading and memory protection (e.g., LoadLibraryA, VirtualProtect), but no overt malicious behavior like C2 communication or data destruction is detected. Thus, it is classified as suspicious, likely a packed executable without cle"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/prompt.txt` exists=`True` bytes=`22916` mtime=`2026-08-09T14:33:18.650191+00:00`
  - sha256: `0baf8b26cf7c4715fb6f0cd3b893ddfe565c10e692b311f2813767606527bdc6`
- **verdict:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/verdict.json` exists=`True` bytes=`4529` mtime=`2026-08-09T14:34:24.342155+00:00`
  - sha256: `7ed751f0981a09e2b54727dddc5e7954d17d90afd8c0544d5f424fad85d46859`

#### prompt_excerpt

```
# Triage evidence
sha256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5
sample_path: /opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe
ghidra_session: ghidra-pe-2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5
ida_session: ida-2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — All tools (ghidra, ida, malcat) report 11 imports, indicating consistent data. Ghidra is chosen as a standard tool for import analysis.
- functions: ida (confidence=medium) — IDA and malcat report 7 functions, while ghidra reports 4. IDA is a reliable tool for function detection and agrees with malcat.
- strings: both (confidence=high) — Large discrepancy between tools (ghidra:40, ida:304, malcat:100). Using both ghidra and ida provides a more comprehensive set of strings.
- decompilation: ghidra (confidence=mediu
… [21879 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "suspicious",
  "score": 50,
  "family_guess": "nSpack",
  "cross_engine_notes": "Multiple tools (packer_intake, yara, floss, malcat) consistently identify nSpack packing. Ghidra reports fewer functions and strings (4 vs 7 in IDA) due to packing obfuscation, while IDA and MalCat agree on imports including memory manipulation APIs. No clear behavioral-intent evidence (e.g., C2, data destruction) is found across engines.",
  "key_evidence": [
    {
      "source": "packer_intake",
      "query_or_table": "label",
      "row_or_rule": "packed",
      "why": "Deterministic analysis flags the sample as packed with high entropy exec sections (e.g., nsp1 entropy 6.961), section mismatches, and checklist indicators like raw_vs_virtual_mismatch and high_entropy_exec_section, consistent with nSpack."
    },
    {
      "source": "yara",
      "query_or_rule": "nSpackV2xLiuXingPing",
      "row_or_rule": "nSpackV2xLiuXingPing rule match",
      "why": "YARA rule specifically detect
… [3529 more chars]
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
    }
  ],
  "timeout_s": 60,
  "sample_size": 55021,
  "duration_s": 0.82,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 55021,
  "duration_s": 0.03,
  "import_count": 11,
  "signal_count": 4,
  "signals": [
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
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
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
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3242,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 6033,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 3112,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "nSpackV2xLiuXingPing",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 27734,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "NsPackV2XLiuXingPing",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 53,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "NsPackv23NorthStar",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 27734,
          "length": 85,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 27734,
          "length": 141,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 27736,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "suspicious_packer_section",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "win_registry",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/26
… [3011 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 169,
  "strings_sampled": 80,
  "strings": [
    "!packed by nspack$@",
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
    "type=\"win32\"",
    "name=\"Microsoft.Windows.Common-Controls\"",
    "version=\"6.0.0.0\"",
    "publicKeyToken=\"6595b64144ccf1df\"",
    "language=\"*\"",
    "</dependentAssembly>",
    "</dependency>",
    "</assembly>",
    "dDDDDDDDDDDDDD@",
    "fffffffffffff@",
    "opopopopowwpf@",
    "opopopopopopf@",
    "`wwwwwwwfffff@",
    "fffff@",
    "ffffffffffffffa",
    "fDDDDDD@offffff@n`",
    "p@offffff@n`",
    "@offffff@n",
    "wwwff@o",
    "ffffffa",
    "B--B5J",
    "|||ddcO87",
    "c||cO87",
    "=||ccOM7",
    "6=cc=4",
    "`NfOM79|?4",
    "`~bbbi",
    "xrssssvvvv",
    "^zwurqqqqqsssssvvvv;",
    "^;LLZZzxxwtrqqrZ",
    "f^NLLL",
    "YYYYXXV",
    "XXXXXVX",
    "*4!XT?=,",
    "![kT@2P?.,",
    "*2#[q7",
    "kR26?.,",
    "AXk=N3-",
    "0TO>?.(",
    "hBqP<S",
    "UAYT5R:",
    "9DP0l@4",
    "o9TP>p4",
    "UBWk6lJ",
    "WpC?/>",
    "}}}~~~a",
    "`}}}bm",
    "cDfLMGN^J",
    "n?UKVWXC;",
    "FBA23>@S",
    "KERNEL32.DLL",
    "SHELL32.DLL",
    "MSVCRT.DLL",
    "ADVAPI32.DLL",
    "GDI32.DLL",
    "USER32.DLL",
    "LoadLibraryA",
    "GetProcAddress",
    "VirtualProtect",
    "VirtualAlloc",
    "VirtualFree",
    "ExitProcess",
    "ShellAboutW",
    "__CxxFrameHandler",
    "RegOpenKeyExA",
    "SetBkColor",
    "GetMenu",
    "y<w:~s",
    "U.X-.]_"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 169
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 6.18,
  "size_bytes": 55021,
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
  "sample": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
  "disassembly": {
    "0x0100101b": "\u250c 5: entry0 ();\n\u2514       \u250c\u2500< 0x0100101b      e9364a0200     jmp fcn.01025a56",
    "0x01025a56": "\u254e   ; CODE XREF from entry0 @ 0x100101b(x)\n\u251c 648: fcn.01025a56 ();\n\u2502       \u254e   ; var int32_t var_1beh @ ebp-0x1be\n\u2502       \u254e   ; var int32_t var_1c2h @ ebp-0x1c2\n\u2502       \u254e   ; var int32_t var_1c6h @ ebp-0x1c6\n\u2502       \u254e   ; var int32_t var_1cah @ ebp-0x1ca\n\u2502       \u254e   ; var int32_t var_1fah @ ebp-0x1fa\n\u2502       \u254e   ; var int32_t var_202h @ ebp-0x202\n\u2502       \u254e   ; var int32_t var_212h @ ebp-0x212\n\u2502       \u254e   ; var int32_t var_22ah @ ebp-0x22a\n\u2502       \u254e   ; var int32_t var_23eh @ ebp-0x23e\n\u2502       \u254e   ; var int32_t var_246h @ ebp-0x246\n\u2502       \u254e   ; var int32_t var_26eh @ ebp-0x26e\n\u2502       \u254e   ; var int32_t var_27eh @ ebp-0x27e\n\u2502       \u254e   0x01025a56      9c             pushfd\n\u2502       \u254e   0x01025a57      60             pushal\n\u2502       \u254e   0x01025a58      e800000000     call 0x1025a5d\n\u2502       \u254e   ; CALL XREF from fcn.01025a56 @ 0x1025a58(x)\n\u2502       \u254e   0x01025a5d      5d             pop ebp\n\u2502       \u254e   0x01025a5e      b807000000     mov eax, 7\n\u2502       \u254e   0x01025a63      2be8           sub ebp, eax\n\u2502       \u254e   0x01025a65      8db5d6fdffff   lea esi, [var_22ah]\n\u2502       \u254e   0x01025a6b      8b06           mov eax, dword [esi]\n\u2502       \u254e   0x01025a6d      83f800         cmp eax, 0\n\u2502      \u250c\u2500\u2500< 0x01025a70      7411           je 0x1025a83\n\u2502      \u2502\u254e   0x01025a72  ~   8db5fefdffff   lea esi, [var_202h]\n..\n\u2502      \u2502\u254e   0x01025a78      8b06           mov eax, dword [esi]\n\u2502      \u2502\u254e   0x01025a7a      83f801         cmp eax, 1                  ; 1\n\u2502     \u250c\u2500\u2500\u2500< 0x01025a7d      0f844b020000   je 0x1025cce\n\u2502     \u2502\u2514\u2500\u2500> 0x01025a83  ~   c70601000000   mov dword [esi], 1\n..\n\u2502     \u2502 \u254e   0x01025a89      8bd5           mov edx, ebp\n\u2502     \u2502 \u254e   0x01025a8b      8b8592fdffff   mov eax, dword [var_26eh]\n\u2502     \u2502 \u254e   0x01025a91      2bd0           sub edx, eax\n\u2502     \u2502 \u254e   0x01025a93      899592fdffff   mov dword [var_26eh], edx\n\u2502     \u2502 \u254e   0x01025a99      0195c2fdffff   add dword [var_23eh], edx\n\u2502     \u2502 \u254e   0x01025a9f      8db506feffff   lea esi, [var_1fah]\n\u2502     \u2502 \u254e   0x01025aa5      0116           add dword [esi], edx\n\u2502     \u2502 \u254e   0x01025aa7      8b36           mov esi, dword [esi]\n\u2502     \u2502 \u254e   0x01025aa9      8bfd           mov edi, ebp\n\u2502     \u2502 \u254e   0x01025aab      60             pushal\n\u2502     \u2502 \u254e   0x01025aac      6a40           push 0x40                   ; pe_nt_image_headers32\n\u2502     \u2502 \u254e   0x01025aae      6800100000     push 0x1000\n\u2502     \u2502 \u254e   0x01025ab3      6800100000     push 0x1000\n\u2502     \u2502 \u254e   0x01025ab8      6a00           push 0\n\u2502     \u2502 \u254e   0x01025aba      ff953afeffff   call dword [var_1c6h]\n\u2502     \u2502 \u254e   0x01025ac0      85c0           test eax,
… [4116 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 00000040 PE..L.....};.........................."
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000040 PE..L.....};..........................\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
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
    "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.DLL!LoadLibraryA",
      "KERNEL32.DLL!GetProcAddress",
      "KERNEL32.DLL!VirtualProtect",
      "KERNEL32.DLL!VirtualAlloc",
      "KERNEL32.DLL!VirtualFree",
      "SHELL32.DLL!ShellAboutW",
      "MSVCRT.DLL!__CxxFrameHandler",
      "ADVAPI32.DLL!RegOpenKeyExA",
      "GDI32.DLL!SetBkColor",
      "USER32.DLL!GetMenu"
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
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "YARA rules nSpackV2xLiuXingPing and NsPackv23NorthStar matched; string '!packed by nspack$@' at file offset confirms nSp",
    "Version info masquerades as 'Microsoft Windows Calculator' (CALC.EXE) v5.1.2600.0 by Microsoft Corporation \u2014 forged meta",
    "Imports include VirtualAlloc, VirtualFree, VirtualProtect, LoadLibraryA, GetProcAddress, RegOpenKeyExA \u2014 APIs associated",
    "capa detected 'decompress data using aPLib' (C0025.003) \u2014 the packer uses aPLib to decompress the hidden payload at runt",
    "Sections nsp0 (122880 bytes) and nsp1 (61520 bytes) both have RWX permissions (is_read=1, is_write=1, is_exec=1) \u2014 class"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "PE executable packed with nSpack v2.x that masquerades as Windows Calculator (calc.exe). The binary uses forged Microsoft Corporation version info to disguise itself. It contains aPLib decompression routines, VirtualAlloc/VirtualProtect for memory manipulation, dynamic API resolution via LoadLibrary",
  "key_evidence": [
    "YARA rules nSpackV2xLiuXingPing and NsPackv23NorthStar matched; string '!packed by nspack$@' at file offset confirms nSpack v2.x packer",
    "Version info masquerades as 'Microsoft Windows Calculator' (CALC.EXE) v5.1.2600.0 by Microsoft Corporation \u2014 forged metadata on a packed binary",
    "Imports include VirtualAlloc, VirtualFree, VirtualProtect, LoadLibraryA, GetProcAddress, RegOpenKeyExA \u2014 APIs associated with unpacking, dynamic resolution, and registry access",
    "capa detected 'decompress data using aPLib' (C0025.003) \u2014 the packer uses aPLib to decompress the hidden payload at runtime",
    "Sections nsp0 (122880 bytes) and nsp1 (61520 bytes) both have RWX permissions (is_read=1, is_write=1, is_exec=1) \u2014 classic self-modifying code indicator",
    "YARA win_registry rule hit at offsets 27512 and 27674; IP rule hit at offset 3242; contains_base64 hit at offset 3112; maldoc_getEIP_method_1 hit at offset 27736",
    "Main function FUN_01025d7f has cyclomatic complexity 18 with 27 basic blocks indicating obfuscated control flow in the packer stub",
    "Only 4 functions identified statically \u2014 the real payload is hidden inside the compressed nsp1 section and not accessible without runtime unpacking"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
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
      "path
… [6111 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
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
    "file_name": "nspack.exe",
 
… [52126 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 1,
  "top_rules": [
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
    }
  ],
  "
… [137 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 55021,
  "duration_s": 0.03,
  "import_count": 11,
  "signal_count": 4,
  "signals": [
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
      "label": 
… [301 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 169,
  "strings_sampled": 80,
  "strings": [
    "!packed by nspack$@",
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">",
    "<assemblyIdentity",
    "name=\"Microsoft.Windows.Shell.calc\"",
    "processorArchitecture=\"x86\"",
    "version=\"5.1.0.0\"",

… [1816 more chars]
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
  "sample": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
  "disassembly": {
    "0x0100101b": "\u250c 5: entry0 ();\n\u2514       \u250c\u2500< 0x0100101b      e9364a0200     jmp fcn.01025a56",
    "0x01025a56": "\u254e   ; CODE XREF from entry0 @ 0x100101b(x)\n\u251c 648: fcn.01025a56 ();\n\u2502     
… [7216 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 
… [9 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 00000040 PE..L.....};.........................."
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000040 PE..L.....};..........................\n",
  "xorsearch_stderr": "
… [32 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
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
    "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.DLL!LoadLibraryA",
      "KERNEL32.DLL!GetProcAddress",
      "KERNEL32.DLL!VirtualProtect",
      "KERNEL32.DLL!VirtualAlloc",
 
… [208 more chars]
```

- **shellcode_extract** ok=`True` checklist=`True` — Required checklist tool (shellcode)

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
  "sections_analyzed": [
    {
      "name": "nsp0",
      "size": 303,
      "entropy": 2.196,
      "executable": true,
      "writable": true
    },
    {
      "name": "nsp1",
      "size": 54509,
      "entropy": 6.961,
      "execut
… [606 more chars]
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals + emulation oracle + unpack pass

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 0.09,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.04,
 
… [352 more chars]
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
      "name": "FUN_01025d7f",
      "address": "16932223",
      "size": "131"
    },
    {
      "name": "FUN_01025e0a",
      "address": "16932362",
      "size": "16"
    },
    {
      "name": "FUN_01025dfe",
      "address": "16932350",
      "size": "10"
    },
    {
      "name": "FUN_01025e08",
      "address": "
… [340 more chars]
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
      "name": "RegOpenKeyExA",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "SetBkColor",
      "module": "GDI32.DLL"
    },
    {
      "name": "ExitProcess",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetProcAddress",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "LoadLibraryA",
      "modul
… [771 more chars]
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
      "content": "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n<assemblyIdentity\r\n    name=\"Microsoft.Windows.Shell.calc\"\r\n    processorArchitecture=\"x86\"\r\n    version=\"5.1.0.0\"\r\n    type=\"win32\"/>\r\n<description>
… [3756 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n<assemblyIdentity\r\n    name=\"Microsoft.Windows.Shell.calc\"\r\n    processorArchitecture=\"x86\"\r\n    version=\"5.1.0.0\"\r\n    type=\"win32\"/>\r\n<description>
… [3114 more chars]
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `idasql SQL error: no such function: REGEXP`

```json
{
  "error": "idasql SQL error: no such function: REGEXP"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such function: REGEXP`

```json
{
  "error": "ghidrasql SQL error: no such function: REGEXP"
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
      "content": "CALC.EXE",
      "address": "16906428"
    },
    {
      "content": "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n<assemblyIdentity\r\n    name=\"Microsoft.Windows.Shell.calc\"\r\n    processorArchitecture=\"x86
… [1274 more chars]
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
      "content": "Windows Calculator application file",
      "address": "16906044"
    },
    {
      "content": "CALC",
      "address": "16906248"
    },
    {
      "content": "CALC.EXE",
      "address": "16906428"
    },
    {
      "content": "Microsoft\u00ae Windows\u00ae Operating System",
      "address": "16906480"
   
… [1255 more chars]
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
      "name": "FUN_01025d7f",
      "address": "16932223",
      "size": "131",
      "cyclomatic_complexity": "18",
      "instruction_count": "54",
      "block_count": "27",
      "call_out_count": "7
… [1078 more chars]
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
      "start_ea": "16777216",
      "end_ea": "16778239",
      "name": "Headers",
      "class": "DATA",
      "perm": "4",
      "bitness": "0",
      "size": "1024",
      "is_read": "1",
      "is_write": "0",
      "
… [818 more chars]
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
      "content": "VS_VERSION_INFO",
      "address": "16905782"
    },
    {
      "content": "StringFileInfo",
      "address": "16905874"
    },
    {
      "content": "040904B0",
      "address": "16905910"
    },
    {
      "content": "CompanyName",
      "address": "16905934"
    },
    {
      "content": "Microsoft Corpora
… [3692 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "src_func_addr",
    "src_func_name",
    "dst_func_addr",
    "dst_func_name",
    "call_site"
  ],
  "rows": [
    {
      "src_func_addr": "16932223",
      "src_func_name": "FUN_01025d7f",
      "dst_func_addr": "16932350",
      "dst_func_name": "FUN_01025dfe",
      "call_site": "16932236"
    },
    {
      "src_func_addr": "16932223",
      "src_func_name": "FUN_01025d
… [1757 more chars]
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
      "address": "16781339",
      "name": "entry",
      "module": "Global"
    },
    {
      "address": "16893912",
      "name": "Rsrc_Menu_6a_409",
      "module": "Global"
    },
    {
      "address": "16894192",
      "name": "Rsrc_Menu_6b_409",
      "module": "Global"
    },
    {
      "address": "16894664",
… [4215 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5.json"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "func_name",
    "func_addr"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5",
  "audit_path": "/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/audit.jsonl"
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 1,
  "top_rules": [
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
    }
  ],
  "
… [137 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 169,
  "strings_sampled": 80,
  "strings": [
    "!packed by nspack$@",
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">",
    "<assemblyIdentity",
    "name=\"Microsoft.Windows.Shell.calc\"",
    "processorArchitecture=\"x86\"",
    "version=\"5.1.0.0\"",

… [1816 more chars]
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
  "session_id": "ghidra-pe-2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5",
  "audit_path": "/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/audit.jsonl"
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
  "rows": [
    {
      "name": "FUN_01025d7f",
      "address": "16932223",
      "size": "131"
    },
    {
      "name": "FUN_01025dfe",
      "address": "16932350",
      "size": "10"
    },
    {
      "name": "FUN_01025e08",
      "address": "16932360",
      "size": "2"
    },
    {
      "name": "FUN_01025e0a",
      "address": "1
… [340 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/deep_dive/01-tools-raw.json` exists=`True` bytes=`79563` mtime=`2026-08-09T14:34:51.110168+00:00`
  - sha256: `daf831d591bfdaffe57986ee942a7bbfb371e5085305847917d62413b2cf56e9`
- **sql_evidence:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/deep_dive/05-deep-dive.json` exists=`True` bytes=`4084` mtime=`2026-08-09T14:37:46.476500+00:00`
  - sha256: `5958cb73ec305bad4d5ef6c7ddecb98c871da5a223ca5705da0e3e1bef7b4d0c`

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
  "summary": "PE executable packed with nSpack v2.x that masquerades as Windows Calculator (calc.exe). The binary uses forged Microsoft Corporation version info to disguise itself. It contains aPLib decompression routines, VirtualAlloc/VirtualProtect for memory manipulation, dynamic API resolution via LoadLibraryA/GetProcAddress, and registry access (RegOpenKeyExA). Both code sections (nsp0/nsp1) have RWX permissions indicating self-modifying unpacking code. YARA rules detect embedded IP addresses, registry keys, base64-encoded data, and position-independent code techniques. The actual malicious payload is compressed/encrypted and only revealed at runtime after unpacking. Persistence m
… [3284 more chars]
```

- **agentic:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`278180` mtime=`2026-08-09T14:37:46.475500+00:00`
  - sha256: `9f20ca7c959ff3db39deb7570e11dd72ebe92a6c610ac10c0817eb98fe6f8338`

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

- **rule_yar:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/rule.yar` exists=`True` bytes=`1287` mtime=`2026-08-09T14:40:33.649763+00:00`
  - sha256: `7e4fa4e4f5d4f8da4a9998c1c7dd66eee6008f3a84d00c2e732b92c1cf4f732e`

#### excerpt

```
// yara_gen_v2.py — 2026-08-09T14:40:33.650907+00:00
import "pe"
rule CADRE_v2_nspack_2627682eb7e8 {
    meta:
        description = "RevAI v2 auto rule for nSpack"
        sha256 = "2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5"
        family = "nspack"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!packed by nspack$@" ascii wide
        $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" ascii wide
        $s2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" ascii wide
        $s3 = "<assemblyIdentity" ascii wide
        $s4 = "name=\"Microsoft.Windows.Shell.calc\"" ascii wide
        $s5 = "p
… [485 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/REPORT-MASTER-v2.md` exists=`True` bytes=`14153` mtime=`2026-08-09T14:44:35.348330+00:00`
  - sha256: `f88581fef355e781ed7c4b713388f619678aee88347c73058d3be6f333bf544d`
- **REPORT_MASTER_v3:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/REPORT-MASTER-v3.md` exists=`True` bytes=`47876` mtime=`2026-08-09T14:58:37.457429+00:00`
  - sha256: `0bd63812602390a5261f539df4dd9083e0be8250b24afca1d4f1823b60f7753d`
- **REPORT_v2:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/REPORT-v2.md` exists=`True` bytes=`14153` mtime=`2026-08-09T14:44:35.348330+00:00`
  - sha256: `f88581fef355e781ed7c4b713388f619678aee88347c73058d3be6f333bf544d`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`64426` mtime=`2026-08-09T14:51:26.830387+00:00`
  - sha256: `cb14605f5fa06a3740e691b08d580761d83055977e747d57f6871e59f015d7f0`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`46557` mtime=`2026-08-09T15:05:58.686523+00:00`
  - sha256: `e65404ab2701284977396695e050590196b61d8ce8bd50d30eb5b30b3964f711`
- **report_v2_json:** `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/report-v2.json` exists=`True` bytes=`17186` mtime=`2026-08-09T14:51:26.832387+00:00`
  - sha256: `8e80a6e30a51de07434bb69fcb22d51e021c5beb40757944ba0b5898423afc0f`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 14:44:35 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: nSpackV2xLiuXingPing, NsPackV2XLiuXingPing, NsPackv23NorthStar, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasModified_DOS_Message, suspicious_packer_section). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** nSpack
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see w
… [13242 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 14:58:37 UTC

# RE Report — 2627682eb7e8
_Generated 2026-08-09T14:58:37.454898+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=89.03s -->

## Executive Summary

This section synthesizes the top-line assessment of the malware sample (SHA256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5), focusing on verdict, family, confidence, and a concise summary.

### Top-Line Verdict

| Attribute | Value | Confidence | Evidence Source & Interpretation |
|-----------|-------|------------|----------------------------------|
| Verdict    | Su
… [46949 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
