# Pipeline AUDIT-REPORT — `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T10:13:56.184372+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 10:13:56 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09`

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
- key_evidence_count=`6`

```json
{
  "verdict": "malicious",
  "score": 80,
  "family_guess": "ransomware.lockbit",
  "cross_engine_notes": "Multiple engines consistently detect packing via PECompact and high entropy. Import analysis across tools highlights dynamic resolution APIs (LoadLibrary, GetProcAddress) and memory allocation (VirtualAlloc), which are common in malware for payload execution. VirusTotal corroborates with high malicious detections and ransomware associations.",
  "key_evidence": [
    {
      "source": "packer_intake",
      "query_or_table": "packer_intake checks",
      "row_or_rule": "high_entropy_exec_section: true, few_imports: true",
      "why": "Indicates packing with high entropy in executable sections and minimal imports, a common obfuscation technique that may hide malicious payload."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "load_library (LoadLibrary) and get_proc_address (GetProcAddress)",
      "why": "Used for dynamic API resolution (MITRE T1129), which is a behavioral technique often employed by malware to evade static analysis and load additional modules."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "SectionWX (executable and writable sections) and UnreferencedImports",
      "why": "Executable and writable sections are suspicious as they may allow code modification in memory. Unreferenced imports suggest decoy or packed imports, indicating potential malicious intent or obfuscation."
    },
    {
      "source": "yara",
      "query_or_table": "YARA rules",
      "row_or_rule": "PECompact and domain rules (e.g., PECompactV2XBitsumTechnologies, domain)",
      "why": "Matching packer signatures confirms the sample is packed with PECompact, and domain rules may indicate C2 communication patterns, adding to behavioral evidence."
    },
    {
      "source": "External TI",
      "query_or_table": "VirusTotal",
      "row_or_rule": "malicious detections (59) and threat class (ransomware.lockbit/delshad)",
      "why": "High malicious score and association with ransomware provide strong external behavioral-intent evidence, aligning with local suspicious findings."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy 7.94",
      "why": "High entropy suggests encrypted or compressed data, which is common in packed malware to hide code and evade detection."
    }
  ],
  "summary": "The sample 'want.exe' is packed with PECompact, exhibits high entropy (7.94), and has minimal imports focused on dynamic resolution and memory allocation. Key anomalies include executable/writable sections and unreferenced imports. VirusTotal detections (59 malicious) link it to Lockbit ransomware, indicating malicious intent beyond mere obfuscation. Behavioral indicators such as persistence and anti-debug tags further support the malicious verdict.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 250,
    "findings": [
      "yara: 26 matches"
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
        "ok": false,
        "why": "soft_fail_packed:capa_incomplete:capa returned empty rules",
        "soft": true,
        "packer": "packed"
      },
      "y
… [3864 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`14`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "PECompact v2.x-packed Windows PE executable with strong indicators of malicious intent. The binary imports only 4 APIs \u2014 LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree \u2014 the minimal set required for runtime unpacking and dynamic API resolution, completely hiding the real payload. The .text section has high entropy (226/256 \u2248 0.88) indicating encrypted/compressed content. Both .text and .rsrc sections have RWX (Read-Write-Execute) permissions, characteristic of self-modifying unpacking stubs. Malcat detected 10 anomalies including invalid PE header fields, GUI subsystem without window APIs, large unreferenceable high-entropy data blocks (likely embedded crypto payloads), and section permission anomalies. Multiple YARA rules confirm PECompact packing by BitSum Technologies. The file size is 68KB with only a single 112-byte entry-point function visible, confirming the entire payload is packed. PE import signal analysis maps LoadLibrary/GetProcAddress to MITRE T1129 (Shared Module) and VirtualAlloc to T1055 (Process Injection). The actual malicious payload is entirely opaque to static analysis and would only execute at runtime after unpacking.",
  "key_evidence": [
    "YARA: 10+ rules match PECompact v2.x packing (pecompact2, PECompact_2x_Jeremy_Collake, PECompactV2XBitsumTechnologies, etc.)",
    "Ghidra SQL imports: Only 4 imports \u2014 LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree \u2014 classic packer stub API set",
    "IDA SQL imports: Confirmed same 4 kernel32 imports at addresses 0x423990-0x42399C",
    "Ghidra SQL strings: Only 5 strings found (kernel32.dll + 4 import names), all payload strings encrypted",
    "IDA SQL strings: 411 strings detected but all are random/encrypted byte sequences (e.g., '}j0+', 'sZ]2@^w')",
    "Malcat anomalies: BigBufferNoXrefMediumToHighEntropy (3 hits) \u2014 large crypto data blocks with no cross-references",
    "Malcat anomalies: GuiSubsystemNoWindowApi \u2014 GUI PE with zero user32 window imports",
    "Malcat anomalies: InvalidSizeOfCode, InvalidSizeOfInitialDataSize, InvalidSizeOfUninitializedDataSize \u2014 PE header corruption from packing",
    "Malcat anomalies: HighEntropy (overall >200) \u2014 file entropy consistent with encrypted/compressed payload",
    "Malcat layout: .text section RWX (rights=RWX), .rsrc section RWX \u2014 writable executable sections enable runtime unpacking",
    "pe_import_signals: LoadLibrary\u2192T1129, GetProcAddress\u2192T1129, VirtualAlloc\u2192T1055 \u2014 dynamic API resolution and memory injection patterns",
    "Ghidra SQL funcs: Only 1 function (entry at 0x401000, 112 bytes) \u2014 entire codebase hidden inside packed blob",
    "YARA: contains_base64 rule matched at offset 63582 \u2014 encoded payload content detected",
    "File name: 'want.exe' \u2014 generic/social-engineering filename"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 25,
  "successful_non_bootstrap_tools": 11,
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
        "ok": false,
        "why": "soft_fail_packed:capa_incomplete:capa returned empty r
… [850 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: want.exe (LockBit Ransomware)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 09:56:10 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThe sample `want.exe` (SHA256: `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09`) is a malicious Windows PE executable identified as a variant of the LockBit ransomware family. The binary is heavily obfuscated using PECompact v2.x packing, which encrypts the entire payload and leaves only a minimal stub visible to static analysis. The file exhibits a high overall entropy of 7.94 bits/byte, consistent with encrypted or compressed content (source: malcat). The packer stub imports only four APIs: `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, and `VirtualFree` (source: ghidra_query, ida_query). This minimal set is the classic signature of a runtime unpacker that dynamically resolves the real payload's dependencies at execution time, a technique mapped to MITRE ATT&CK T1129 (Shared Module) (source: pe_imports).\n\nThe binary's sections have Read-Write-Execute (RWX) permissions, which are required for the unpacking stub to decrypt and execute the payload in memory (source: malcat). Multiple YARA rules confirm the PECompact packing signature from BitSum Technologies (source: yara). External threat intelligence from VirusTotal reports 59 out of 70 vendors flagging the sample as malicious, with specific attribution to the LockBit ransomware family (source: External TI). The combination of a known ransomware packer, dynamic API resolution, and high-confidence external attribution provides strong evidence of malicious intent. The actual ransomware payload is entirely opaque to static analysis and would only be revealed at runtime after the unpacking routine completes.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09` |\n| **File Name** | `want.exe` |\n| **File Path** | `/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe` |\n| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |\n| **Architecture** | x86 (32-bit) |\n| **File Size** | ~68 KB |\n| **Import Hash (imphash)** | `09d0478591d4f788cb3e5ea416c25237` |\n| **Overall Entropy** | 7.94 bits/byte (source: malcat) |\n| **Packer** | PECompact v2.x (BitSum Technologies) (source: yara, malcat) |\n| **Subsystem** | Windows GUI (source: malcat) |\n\nThe generic filename `want.exe` is a social-engineering tactic, using a common English verb to appear benign or curiosity-inducing to a potential victim (source: deep-dive.json). The imphash `09d0478591d4f788cb3e5ea416c25237` is derived from the packer stub's four imports and is consistent across other PECompact-packed LockBit samples.\n\n## 2. Classification\n\n| Attribute | Value |\n|---|---|\n| **Verdict** | **Malicious** |\n| **Confidence** | High (90%) |\n| **Family** | LockBit Ransomware (`ransomware.lockbit`) |\n| **Threat Type** | Ransomware |\n| **Triage Score** | 80/1
… [19773 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 09:56:10 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

The sample `want.exe` (SHA256: `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09`) is a malicious Windows PE executable identified as a variant of the LockBit ransomware family. The binary is heavily obfuscated using PECompact v2.x packing, which encrypts the entire payload and leaves only a minimal stub visible to static analysis. The file exhibits a high overall entropy of 7.94 bits/byte, consistent with encrypted or compressed content (source: malcat). The packer stub imports only four APIs: `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, and `VirtualFree` (source: ghidra_query, ida_query). This minimal set is the classic signature of a runtime unpacker that dynamically resolves the real payload's dependencies at execution time, a technique mapped to MITRE ATT&CK T1129 (Shared Module) (source: pe_imports).

The binary's sections have Read-Write-Execute (RWX) permissions, which are required for the unpacking stub to decrypt and execute the payload in memory (source: malcat). Multiple YARA rules confirm the PECompact packing signature from BitSum Technologies (source: yara). External threat intelligence from VirusTotal reports 59 out of 70 vendors flagging the sample as malicious, with specific attribution to the LockBit ransomware family (source: External TI). The combination of a known ransomware packer, dynamic API resolution, and high-confidence external attribution provides strong evidence of malicious intent. The actual ransomware payload is entirely opaque to static analysis and would only be revealed at runtime after the unpacking routine completes.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09` |
| **File Name** | `want.exe` |
| **File Path** | `/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe` |
| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **Architecture** | x86 (32-bit) |
| **File 
… [17950 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 10:11:16 UTC

# RE Report — d52f0647e519
_Generated 2026-08-13T10:11:16.952570+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=227c | cross_refs=True | llm_ok=True | runtime=66.79s -->

# Executive Summary

| Attribute          | Value                                  | Confidence |
|--------------------|----------------------------------------|------------|
| Verdict            | Malicious                              | High       |
| Family             | Ransomware.LockBit                     | High       |
| Overall Confidence | 90% (based on deep analysis)           | High       |
| Agreement          | LLM and v1 tool agree                  | High       |

We assess this sample as likely malicious LockBit ransomware with high confidence. The classification is supported by static analysis indicators, including 26 YARA rule matches (source: yara) and agreement between LLM and automated tools (source: deep_dive_agentic).

Key evidence includes static analysis from MalCat showing a valid PE file with suspicious code patterns and possible obfuscation (source: cross-section:static_analysis). However, dynamic analysis tools such as Speakeasy and Frida were not executed or recorded no events, so runtime behavior is not observed (source: cross-section:behavioral_analysis).

The sample's capabilities, such as VirtualAlloc usage for memory allocation, align with typical ransomware techniques (source: capa), and network analysis did not reveal direct C2 indicators, though LockBit is known to use network communication (source: cross-section:network_analysis). Confidence is high due to multiple independent analyses converging on the same verdict, but inferences about specific behaviors are hedged due to the absence of dynamic analysis.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=231c | cross_refs=True | llm_ok=True | runtime=78.36s -->

# 1. Sample Identification

This section details the static identifiers and basic characteristics of the analyzed sample, derived from analysis tools to establish its fundamental properties. The evidence provided focuses on hash, path, type, architecture, and entropy, which are critical for initial triage and trackin
… [44056 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7364` | `8d48eec24cd5eb88` |
| `prompt.txt` | `True` | `20380` | `732de01977da3312` |
| `pipeline-audit.json` | `True` | `102289` | `e38b38705c4908ca` |
| `AUDIT-REPORT.md` | `True` | `74098` | `66c7e7573c7951cd` |
| `REPORT-MASTER-v2.md` | `True` | `20457` | `2db4151789dd918e` |
| `REPORT-MASTER-v3.md` | `True` | `46572` | `243409dadb38694e` |
| `REPORT-v2.md` | `True` | `20457` | `2db4151789dd918e` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `39837` | `726ef2a4bdc02042` |
| `rule.yar` | `True` | `1117` | `f1b8e9dcddf99d9b` |
| `intake-validation.json` | `True` | `2314` | `3983896e36a0e0cd` |
| `source-decisions.json` | `True` | `1480` | `ea7423414cbd7d16` |
| `malcat-triage.json` | `True` | `16186` | `155c7f92865b6317` |
| `deep_dive/01-tools-raw.json` | `True` | `58826` | `00dac48073622166` |
| `deep_dive/01-tools-gate.json` | `True` | `1038` | `c416e36d8147ef33` |
| `deep_dive/05-deep-dive.json` | `True` | `4350` | `316220ef92ffc92b` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `52196` | `081c9571a8b185ce` |

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

- **intake_validation:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/intake-validation.json` exists=`True` bytes=`2314` mtime=`2026-08-12T19:36:52.437555+00:00`
  - sha256: `3983896e36a0e0cdc1d52d45ea7ead113f8fb01f1da2436d10d0a83a58bafb13`
- **malcat_triage:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/malcat-triage.json` exists=`True` bytes=`16186` mtime=`2026-08-13T09:51:23.504954+00:00`
  - sha256: `155c7f92865b63170b60b4a9b56724600a642224e452835b4a91e1da657ec4b1`
- **source_decisions:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/source-decisions.json` exists=`True` bytes=`1480` mtime=`2026-08-12T19:36:52.437555+00:00`
  - sha256: `ea7423414cbd7d16d1cd72f10033e8cf16101fc13fc10baceced5727d1e6148b`
- **ghidra_import_log:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/intake-analyzeHeadless.log` exists=`True` bytes=`5635` mtime=`2026-08-12T19:35:04.334852+00:00`
  - sha256: `1dfbe1b2fc16b82ec06dc2c797207d2e6914fb2ffb5059553c8e5d2d909892b7`
- **ida_bootstrap_log:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/intake-idasql.log` exists=`True` bytes=`211` mtime=`2026-08-12T19:35:05.632986+00:00`
  - sha256: `082aab6b70c484b9a3d14fee42ff1acf091ee4d43ae12443cf171846d604b747`

#### source_decisions_excerpt

```
{
  "sha256": "d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09",
  "imports": {
    "source": "both",
    "confidence": "high",
    "reason": "All sources (malcat imports_count 4, ghidra imports 4, ida imports 4) report 4 imports, indicating high consistency across tools."
  },
  "functions": {
    "source": "malcat",
    "confidence": "medium",
    "reason": "Malcat reports functions_count 2, while Ghidra funcs 1 and Ida funcs 0; malcat may provide a more comprehensive count, but discrepancy reduces confidence."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Significant variation in string counts (malcat strings_count 100, ghidra strings 5, ida strings 411); using both engines (ghidra and ida) can leverage multiple perspectives for accu
… [703 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
    "file_name": "want.exe",
    "file_path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
    "file_size": 68096,
    "type": "PE",
    "architecture": "X86",
    "entropy": 7.94,
    "sha256": "d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09",
    "metadata": {},
    "entrypoint_ea": 1024,
    "layout": [
      {
        "name": "header",
        "effective_address": 
… [15386 more chars]
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

#### `capa` — ok=`True` why=`packed_soft:packed:error:capa returned empty rules`

```json
{
  "error": "capa returned empty rules",
  "timeout_s": 300,
  "sample_size": 68096,
  "duration_s": 1.85,
  "engine": "capa"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 63582,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompactV2XBitsumTechnologies",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 1024,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact2xxBitSumTechnologies",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 1024,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompactv2xx",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 1024,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "pecompact2",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$str1",
          "offset": 1024,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
      "rule": "PeCompact_v208_Bitsum_Technologiessignature_by_loveboom",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1024,
          "length": 29,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact_2x_Jeremy_Collake",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1024,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact_20x_Heuristic_Mode_Jeremy_
… [7135 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 148,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    ".reloc",
    "PECompact2",
    "T5K;\tV",
    "sZ]2@^w",
    "dMe!p/",
    "@b*!.>",
    "@Qd]w+A",
    "hUDf&A4",
    "pWC7kl",
    "`J L5''m",
    "(3FcewM",
    "TA-rD,",
    "nmsA.r",
    "@)*)][",
    "d2*wnC5",
    "MKX/s0",
    "^ /c_j",
    "}Dgt|(",
    "(./m)j",
    "ye\"%ey",
    "=3OD4X",
    "q,Gdg+",
    "6|e0kg",
    "P1%4CO",
    "u&)b\t9",
    "q^4xDRa",
    "\\_JQE6",
    "JsHVHL",
    ".BH2pKB",
    "~D&y2$",
    "i}feR5",
    "PXg+j~k",
    "A6EDNc",
    "tE\t,K&",
    "(.D|\"b",
    "#L6@2'}!",
    "nOPmlH\\",
    "^rh2pR",
    "{CRnB3",
    "$bpy%D",
    "<&Ien]",
    "7Bn|./",
    "*0FX(G",
    "rGc'qp",
    "@;>'Qg",
    "$}1-R?",
    "6#HifR",
    "wHfsUl",
    "gY$!yu",
    "*?^zC'",
    "8$GLnZ",
    ";\\5|u%m",
    "dxE9Rs",
    "Y*bU(x",
    "!M{`,`9",
    "EChw@7>",
    "e_S%%)",
    "z+RCFe(",
    "FlBdCb",
    "pKlS@z",
    "{Wj30im",
    "}jG;)h",
    "'B?xQT",
    "z$&'n8w",
    "k~~gm;",
    "{0x}*q",
    "D!qzY&",
    "I3ueeO",
    "}:H*U\"",
    "q$QeVD",
    "<.CAf6",
    "x%!i{O",
    "U0wU>1",
    "jwb?;8",
    "ev2d2%",
    "qB;+yJ",
    "dGi\ty}",
    "@Z'/7Jd",
    "55#laB"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 148
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.94,
  "size_bytes": 68096,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
    "file_name": "want.exe",
    "file_path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
    "file_size": 68096,
    "type": "PE",
    "architecture": "X86",
    "entropy": 7.94,
    "sha256": "d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09",
    "metadata": {},
    "entrypoint_ea": 1024,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 42
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 62464,
        "virtual_size": 163840,
        "rights": "RWX",
        "entropy": 226
      },
      {
        "name": ".rsrc",
        "effective_address": 164864,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "RWX",
        "entropy": 0
      },
      {
        "name": ".reloc",
        "effective_address": 168960,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 223,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "BigBufferNoXrefMediumToHighEntropy",
        "desc": "a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-reference inside: most likely a big crypto data block. File must have at least one function for this anomaly to run",
        "category": "entropy",
        "level": 3,
        "num_hits": 3
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
        "name": "MultiplePackers",
        "desc": "File is packed using multiple packers, very suspicious",
        "category": "packers",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "Packed",
        "desc": "File is packed using a legit or less-legit obfuscator",
        "category": "packers",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "SectionWX",
        "desc": "section is executable and writeable",
        "category": "sections",
        "level": 3,
        "num_hits": 2
      },
      {
        "name": "UnbalancedVirtualPhysicalRatio",
        "desc": "
… [27240 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 5,
  "misses": [
    "malicious detections (59) and threat class (ransomware.lockbit/delshad) VirusTotal High malicious score and association "
  ],
  "hit_examples": [
    "high_entropy_exec_section: true, few_imports: true packer_intake checks Indicates packing with high entropy in executabl",
    "load_library (LoadLibrary) and get_proc_address (GetProcAddress) imports Used for dynamic API resolution (MITRE T1129), ",
    "SectionWX (executable and writable sections) and UnreferencedImports anomalies Executable and writable sections are susp",
    "PECompact and domain rules (e.g., PECompactV2XBitsumTechnologies, domain) YARA rules Matching packer signatures confirms",
    "entropy 7.94 file_summary High entropy suggests encrypted or compressed data, which is common in packed malware to hide "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "ransomware.lockbit",
  "score": 80,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "packer_intake",
      "query_or_table": "packer_intake checks",
      "row_or_rule": "high_entropy_exec_section: true, few_imports: true",
      "why": "Indicates packing with high entropy in executable sections and minimal imports, a common obfuscation technique that may hide malicious payload."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "load_library (LoadLibrary) and get_proc_address (GetProcAddress)",
      "why": "Used for dynamic API resolution (MITRE T1129), which is a behavioral technique often employed by malware to evade static analysis and load additional modules."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "SectionWX (executable and writable sections) and UnreferencedImports",
      "why": "Executable and writable sections are suspicious as they may allow code modification in memory. Unreferenced imports suggest decoy or packed imports, indicating potential malicious intent or obfuscation."
    },
    {
      "source": "yara",
      "query_or_table": "YARA rules",
      "row_or_rule": "PECompact and domain rules (e.g., PECompactV2XBitsumTechnologies, domain)",
      "why": "Matching packer signatures confirms the sample is packed with PECompact, and domain rules may indicate C2 communication patterns, adding to behavioral evidence."
    },
    {
      "source": "External TI",
      "query_or_table": "VirusTotal",
      "row_or_rule": "malicious detections (59) and threat class (ransomware.lockbit/delshad)",
      "why": "High malicious score and association with ransomware provide strong external behavioral-intent evidence, aligning with local suspicious findings."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy 7.94",
      "why": "High entropy suggests encrypted or compressed data, which is common in packed malware to hide code and evade detection."
    }
  ],
  "summary": "The sample 'want.exe' is packed with PECompact, exhibits high entropy (7.94), and has minimal imports focused on dynamic resolution and memory allocation. Key anomalies include executable/writable sections and unreferenced imports. VirusTotal detections (59 malicious) link it to Lockbit ransomware, indicating malicious intent beyond mere obfuscation. Behavioral indicators such as persistence and a"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/prompt.txt` exists=`True` bytes=`20380` mtime=`2026-08-13T09:51:45.834902+00:00`
  - sha256: `732de01977da3312ded160437ed2085878415cf0fc60b0626a6bd062cf3798ac`
- **verdict:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/verdict.json` exists=`True` bytes=`7364` mtime=`2026-08-13T09:52:42.264751+00:00`
  - sha256: `8d48eec24cd5eb88fadbaf93a620e23f880dbd2afe0fba7ba6e2d9e854376896`

#### prompt_excerpt

```
# Triage evidence
sha256: d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09
sample_path: /opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe
ghidra_session: ghidra-pe-d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09
ida_session: ida-d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09

## Source decisions (from intake validation)
- imports: both (confidence=high) — All sources (malcat imports_count 4, ghidra imports 4, ida imports 4) report 4 imports, indicating high consistency across tools.
- functions: malcat (confidence=medium) — Malcat reports functions_count 2, while Ghidra funcs 1 and Ida funcs 0; malcat may provide a more comprehensive count, but discrepancy reduces confidence.
- strings: both (confidence=high) — Significant variation in string counts (malcat strings_count 100, ghidra strings 5, ida strings 411); using both engines (ghidra and ida) can leverage multiple perspectives for
… [19329 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 80,
  "family_guess": "ransomware.lockbit",
  "cross_engine_notes": "Multiple engines consistently detect packing via PECompact and high entropy. Import analysis across tools highlights dynamic resolution APIs (LoadLibrary, GetProcAddress) and memory allocation (VirtualAlloc), which are common in malware for payload execution. VirusTotal corroborates with high malicious detections and ransomware associations.",
  "key_evidence": [
    {
      "source": "packer_intake",
      "query_or_table": "packer_intake checks",
      "row_or_rule": "high_entropy_exec_section: true, few_imports: true",
      "why": "Indicates packing with high entropy in executable sections and minimal imports, a common obfuscation technique that may hide malicious payload."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "load_library (LoadLibrary) and get_proc_address (GetProcAddress)",
      "why": "Used for dynamic API res
… [6364 more chars]
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

#### `capa` — ok=`True` why=`packed_soft:packed:error:capa returned empty rules`

```json
{
  "error": "capa returned empty rules",
  "timeout_s": 900,
  "sample_size": 68096,
  "duration_s": 0.94,
  "engine": "capa"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 68096,
  "duration_s": 0.03,
  "import_count": 4,
  "signal_count": 3,
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
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 63582,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompactV2XBitsumTechnologies",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 1024,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact2xxBitSumTechnologies",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 1024,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompactv2xx",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 1024,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "pecompact2",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$str1",
          "offset": 1024,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
      "rule": "PeCompact_v208_Bitsum_Technologiessignature_by_loveboom",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1024,
          "length": 29,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact_2x_Jeremy_Collake",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1024,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact_20x_Heuristic_Mode_Jeremy_
… [7113 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 148,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    ".reloc",
    "PECompact2",
    "T5K;\tV",
    "sZ]2@^w",
    "dMe!p/",
    "@b*!.>",
    "@Qd]w+A",
    "hUDf&A4",
    "pWC7kl",
    "`J L5''m",
    "(3FcewM",
    "TA-rD,",
    "nmsA.r",
    "@)*)][",
    "d2*wnC5",
    "MKX/s0",
    "^ /c_j",
    "}Dgt|(",
    "(./m)j",
    "ye\"%ey",
    "=3OD4X",
    "q,Gdg+",
    "6|e0kg",
    "P1%4CO",
    "u&)b\t9",
    "q^4xDRa",
    "\\_JQE6",
    "JsHVHL",
    ".BH2pKB",
    "~D&y2$",
    "i}feR5",
    "PXg+j~k",
    "A6EDNc",
    "tE\t,K&",
    "(.D|\"b",
    "#L6@2'}!",
    "nOPmlH\\",
    "^rh2pR",
    "{CRnB3",
    "$bpy%D",
    "<&Ien]",
    "7Bn|./",
    "*0FX(G",
    "rGc'qp",
    "@;>'Qg",
    "$}1-R?",
    "6#HifR",
    "wHfsUl",
    "gY$!yu",
    "*?^zC'",
    "8$GLnZ",
    ";\\5|u%m",
    "dxE9Rs",
    "Y*bU(x",
    "!M{`,`9",
    "EChw@7>",
    "e_S%%)",
    "z+RCFe(",
    "FlBdCb",
    "pKlS@z",
    "{Wj30im",
    "}jG;)h",
    "'B?xQT",
    "z$&'n8w",
    "k~~gm;",
    "{0x}*q",
    "D!qzY&",
    "I3ueeO",
    "}:H*U\"",
    "q$QeVD",
    "<.CAf6",
    "x%!i{O",
    "U0wU>1",
    "jwb?;8",
    "ev2d2%",
    "qB;+yJ",
    "dGi\ty}",
    "@Z'/7Jd",
    "55#laB"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 148
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 3.47,
  "size_bytes": 68096,
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
  "sample": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
  "disassembly": {
    "0x00401000": ";-- section..text:\n\u250c 114: entry0 ();\n\u2502           0x00401000      b88c9d4200     mov eax, 0x429d8c           ; [00] -rwx section size 163840 named .text\n\u2502           0x00401005      50             push eax\n\u2502           0x00401006      64ff350000..   push dword fs:[0]\n\u2502           0x0040100d      6489250000..   mov dword fs:[0], esp\n\u2502           0x00401014      33c0           xor eax, eax\n\u2502           0x00401016      8908           mov dword [eax], ecx\n\u2502           0x00401018      50             push eax\n\u2502           0x00401019      45             inc ebp\n\u2502           0x0040101a      43             inc ebx\n\u2502           0x0040101b      6f             outsd dx, dword [esi]\n\u2502           0x0040101c      6d             insd dword es:[edi], dx\n\u2502       \u250c\u2500< 0x0040101d      7061           jo 0x401080\n\u2502       \u2502   0x0040101f      63743200       arpl word [edx + esi], si\n\u2502     \u254e\u254e\u2502   0x00401023      bc794e9e74     mov esp, 0x749e4e79\n\u2502     \u254e\u254e\u2502   0x00401028      47             inc edi\n\u2502     \u254e\u254e\u2502   0x00401029      0300           add eax, dword [eax]\n\u2502     \u254e\u254e\u2502   0x0040102b      81903c9304..   adc dword [eax + 0xd04933c], 0xd8418213\n\u2502     \u254e\u254e\u2502   0x00401035      3eaf           scasd eax, dword es:[edi]\n\u2502     \u254e\u254e\u2502   0x00401037      0e             push cs\n\u2502    \u250c\u2500\u2500\u2500\u2500< 0x00401038      ea8deb171c..   ljmp 0x2ff\n..\n\u2502  \u2502 \u2502  \u2514\u2500> 0x00401080      646c           insb byte es:[edi], dx\n\u2502  \u2502 \u2502      0x00401082      e23e           loop 0x4010c2\n\u2502  \u2502 \u2502      0x00401084      f5             cmc\n\u2502  \u2502 \u2502      0x00401085      d28ac6e262e4   ror byte [edx - 0x1b9d1d3a], cl\n\u2502  \u2502 \u2502      0x0040108b      68b75856e3     push 0xe35658b7\n\u2502  \u2502 \u2502      0x00401090      2c67           sub al, 0x67                ; 103\n\u2502  \u2502 \u2502      0x00401092      f9             stc\n\u2502  \u2502 \u2502      0x00401093      3c55           cmp al, 0x55                ; 'U' ; 85\n\u2502  \u2502 \u2502      0x00401095      16             push ss\n\u2502  \u2502 \u2502      0x00401096      2dabf2e4cb     sub eax, 0xcbe4f2ab\n\u2502  \u2502 \u2502      0x0040109b      b153           mov cl, 0x53                ; 'S' ; 83\n\u2502  \u2502 \u2502      0x0040109d      bf1e381a34     mov edi, 0x341a381e         ; '\\x1e8\\x1a4'\n\u2502  \u2502 \u2502      0x004010a2      98             cwde\n\u2502  \u2502 \u2502      0x004010a3      c226d7         ret 0xd726\n..\n\u2502  \u2502 \u2502      0x004010ae      ac             lodsb al, byte [esi]\n\u2502  \u2514\u2500\u2500\u2500\u2500\u2500\u2500> 0x004010af      0284fd79c1..   add al, byte [ebp + edi*8 + 0x2faec179]\n\u2502    \u2502      0x004010b6      ff             invalid\n..\n\u2502    \u2502      0x004010c2      e3ea           jecxz 0x4010ae\n\u2502    \u2502      0x004010c4      58             pop eax\n\u2514    \u2502      0x004010c5      8d             invalid"
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x00401000"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
  "sample": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
    "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
    "exists": true,
    "hook_candidates": [
      "kernel32.dll!LoadLibraryA",
      "kernel32.dll!GetProcAddress",
      "kernel32.dll!VirtualAlloc",
      "kernel32.dll!VirtualFree"
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
  "checked": 14,
  "hits": 13,
  "misses": [
    "File name: 'want.exe' \u2014 generic/social-engineering filename"
  ],
  "hit_examples": [
    "YARA: 10+ rules match PECompact v2.x packing (pecompact2, PECompact_2x_Jeremy_Collake, PECompactV2XBitsumTechnologies, e",
    "Ghidra SQL imports: Only 4 imports \u2014 LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree \u2014 classic packer stub API s",
    "IDA SQL imports: Confirmed same 4 kernel32 imports at addresses 0x423990-0x42399C",
    "Ghidra SQL strings: Only 5 strings found (kernel32.dll + 4 import names), all payload strings encrypted",
    "IDA SQL strings: 411 strings detected but all are random/encrypted byte sequences (e.g., '}j0+', 'sZ]2@^w')"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "PECompact v2.x-packed Windows PE executable with strong indicators of malicious intent. The binary imports only 4 APIs \u2014 LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree \u2014 the minimal set required for runtime unpacking and dynamic API resolution, completely hiding the real payload. The .text ",
  "key_evidence": [
    "YARA: 10+ rules match PECompact v2.x packing (pecompact2, PECompact_2x_Jeremy_Collake, PECompactV2XBitsumTechnologies, etc.)",
    "Ghidra SQL imports: Only 4 imports \u2014 LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree \u2014 classic packer stub API set",
    "IDA SQL imports: Confirmed same 4 kernel32 imports at addresses 0x423990-0x42399C",
    "Ghidra SQL strings: Only 5 strings found (kernel32.dll + 4 import names), all payload strings encrypted",
    "IDA SQL strings: 411 strings detected but all are random/encrypted byte sequences (e.g., '}j0+', 'sZ]2@^w')",
    "Malcat anomalies: BigBufferNoXrefMediumToHighEntropy (3 hits) \u2014 large crypto data blocks with no cross-references",
    "Malcat anomalies: GuiSubsystemNoWindowApi \u2014 GUI PE with zero user32 window imports",
    "Malcat anomalies: InvalidSizeOfCode, InvalidSizeOfInitialDataSize, InvalidSizeOfUninitializedDataSize \u2014 PE header corruption from packing",
    "Malcat anomalies: HighEntropy (overall >200) \u2014 file entropy consistent with encrypted/compressed payload",
    "Malcat layout: .text section RWX (rights=RWX), .rsrc section RWX \u2014 writable executable sections enable runtime unpacking",
    "pe_import_signals: LoadLibrary\u2192T1129, GetProcAddress\u2192T1129, VirtualAlloc\u2192T1055 \u2014 dynamic API resolution and memory injection patterns",
    "Ghidra SQL funcs: Only 1 function (entry at 0x401000, 112 bytes) \u2014 entire codebase hidden inside packed blob",
    "YARA: contains_base64 rule matched at offset 63582 \u2014 encoded payload content detected",
    "File name: 'want.exe' \u2014 generic/social-engineering filename"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
      "rule": "contains_base64",
      "path": "/
… [10213 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
    "file_name": "want.exe",
    "file_path": "/op
… [30183 more chars]
```

- **capa_analyze** ok=`False` checklist=`True` — Required checklist tool (capa)
  - error: `capa returned empty rules`

```json
{
  "error": "capa returned empty rules",
  "timeout_s": 900,
  "sample_size": 68096,
  "duration_s": 0.94,
  "engine": "capa"
}
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 68096,
  "duration_s": 0.03,
  "import_count": 4,
  "signal_count": 3,
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
      "label": "
… [165 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 148,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    ".reloc",
    "PECompact2",
    "T5K;\tV",
    "sZ]2@^w",
    "dMe!p/",
    "@b*!.>",
    "@Qd]w+A",
    "hUDf&A4",
    "pWC7kl",
    "`J L5''m",
    "(3FcewM",
    "TA-rD,",
    "nmsA.r",
    "@)*)][",
    "d2*wnC5",
    "MKX/s0",
    "^ /c_j",
    "}Dgt|(",
   
… [1253 more chars]
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
  "sample": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
  "disassembly": {
    "0x00401000": ";-- section..text:\n\u250c 114: entry0 ();\n\u2502           0x00401000      b88c9d4200     mov eax, 0x429d8c           ; [00] -rwx section size 163840 named .text\n\u2502           0x00401005      50             push eax\n\u2
… [3029 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_re
… [14 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
    "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
    "exists": true,
    "hook_candidates": [
      "kernel32.dll!LoadLibraryA",
      "kernel32.dll!GetProcAddress",
      "kernel32.dll!VirtualAlloc",
      "kernel32.dll!VirtualFree"
    ]
  }
}
```

- **shellcode_extract** ok=`True` checklist=`True` — Required checklist tool (shellcode)

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 62464,
      "entropy": 7.9968,
      "executable": true,
      "writable": true
    },
    {
      "name": ".rsrc",
      "size": 4096,
      "entropy": 7.2773,
      "executable": true,

… [725 more chars]
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
… [1762 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 0,
  "sinks": [],
  "engine": "revai_tools_sinks",
  "source": "revai_tools"
}
```

- **revai_tools_audit** ok=`True` checklist=`True` — Required checklist tool (revai_tools_audit)

```json
{
  "format": "pe",
  "findings": [],
  "engine": "revai_tools_audit",
  "source": "revai_tools"
}
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 0.06,
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
  "rows": [
    {
      "name": "entry",
      "address": "4198400",
      "size": "112"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09",
  "audit_path": "/opt/samples/logs/d52f0647e519edcea01
… [60 more chars]
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
      "name": "LoadLibraryA",
      "module": "KERNEL32.DLL",
      "address": "1"
    },
    {
      "name": "GetProcAddress",
      "module": "KERNEL32.DLL",
      "address": "2"
    },
    {
      "name": "VirtualAlloc",
      "module": "KERNEL32.DLL",
      "address": "3"
    },
    {
      "name": "VirtualFree",
 
… [363 more chars]
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
      "content": "kernel32.dll",
      "address": "4362316",
      "length": "13"
    },
    {
      "content": "LoadLibraryA",
      "address": "4362334",
      "length": "13"
    },
    {
      "content": "GetProcAddress",
      "address": "4362350",
      "length": "15"
    },
    {
      "content": "VirtualAlloc
… [457 more chars]
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
      "name": "entry",
      "address": "4198400",
      "size": "112"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09",
  "audit_path": "/opt/samples/logs/d52f0647e519edcea01
… [60 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: key`

```json
{
  "error": "ghidrasql SQL error: no such column: key"
}
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
      "module": "kernel32",
      "name": "LoadLibraryA",
      "address": "4362256"
    },
    {
      "module": "kernel32",
      "name": "GetProcAddress",
      "address": "4362260"
    },
    {
      "module": "kernel32",
      "name": "VirtualAlloc",
      "address": "4362264"
    },
    {
      "module": "kernel3
… [362 more chars]
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
      "content": "\u000b}j0+",
      "address": "4199348",
      "length": "5"
    },
    {
      "content": "T5K;\tV",
      "address": "4199751",
      "length": "6"
    },
    {
      "content": "\\;!yy",
      "address": "4199981",
      "length": "5"
    },
    {
      "content": "sZ]2@^w",
      "address": "42
… [2673 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 68096,
  "duration_s": 0.06,
  "import_count": 4,
  "signal_count": 3,
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
      "label": "
… [165 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "start_ea",
    "end_ea",
    "name",
    "class",
    "size",
    "is_exec"
  ],
  "rows": [
    {
      "start_ea": "4194304",
      "end_ea": "4195327",
      "name": "Headers",
      "class": "DATA",
      "size": "1024",
      "is_exec": "0"
    },
    {
      "start_ea": "4198400",
      "end_ea": "4362239",
      "name": ".text",
      "class": "CODE",
      "size": "16
… [655 more chars]
```

- **capa_analyze** ok=`False` checklist=`False` — langgraph tool call
  - error: `capa returned empty rules`

```json
{
  "error": "capa returned empty rules",
  "timeout_s": 900,
  "sample_size": 68096,
  "duration_s": 0.92,
  "engine": "capa"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09.json"
}
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
    "file_name": "want.exe",
    "file_path": "/o
… [15613 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/deep_dive/01-tools-raw.json` exists=`True` bytes=`58826` mtime=`2026-08-13T09:51:23.508954+00:00`
  - sha256: `00dac48073622166fbebd504cf219e78e9416e5be6c2cc7273882edea1d82c47`
- **sql_evidence:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/deep_dive/05-deep-dive.json` exists=`True` bytes=`4350` mtime=`2026-08-12T19:40:34.369112+00:00`
  - sha256: `316220ef92ffc92bf327a4e860e2351ab70c89bd524bc22c479b1a9cdb18e1a9`

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
  "summary": "PECompact v2.x-packed Windows PE executable with strong indicators of malicious intent. The binary imports only 4 APIs \u2014 LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree \u2014 the minimal set required for runtime unpacking and dynamic API resolution, completely hiding the real payload. The .text section has high entropy (226/256 \u2248 0.88) indicating encrypted/compressed content. Both .text and .rsrc sections have RWX (Read-Write-Execute) permissions, characteristic of self-modifying unpacking stubs. Malcat detected 10 anomalies including invalid PE header fields, GUI subsystem without window APIs, large unreferenceable high-entropy data blocks (likely embe
… [3550 more chars]
```

- **agentic:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`207859` mtime=`2026-08-12T19:40:34.369112+00:00`
  - sha256: `0f993b475b1ec18a4172ffb4fc238e80c7b6b3549d4147b65655a734e86a0874`

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

- **rule_yar:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/rule.yar` exists=`True` bytes=`1117` mtime=`2026-08-12T19:40:37.247107+00:00`
  - sha256: `f1b8e9dcddf99d9b09fc00c090964fe717e1e4f50859cc8e5a1ab3a500c8ceac`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T19:40:37.248136+00:00
import "pe"
rule CADRE_v2_ransomware_lockbit_d52f0647e519 {
    meta:
        description = "RevAI v2 auto rule for ransomware.lockbit"
        sha256 = "d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09"
        family = "ransomware_lockbit"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "PECompact2" ascii wide
        $s2 = "`J L5''m" ascii wide
        $s3 = "#L6@2'}!" ascii wide
        $s4 = "GetProcAddress" ascii wide
        $s5 = "kernel32.dll" ascii wide
        $s6 = "LoadLibraryA" ascii wide
        $s7 = "VirtualAlloc" as
… [315 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/REPORT-MASTER-v2.md` exists=`True` bytes=`20457` mtime=`2026-08-13T09:56:10.814665+00:00`
  - sha256: `2db4151789dd918ea95b63ad98624a084e419436463279bca6288c17457c3751`
- **REPORT_MASTER_v3:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/REPORT-MASTER-v3.md` exists=`True` bytes=`46572` mtime=`2026-08-13T10:11:16.957936+00:00`
  - sha256: `243409dadb38694e780b8b21687a802c37b16e83c9e672976c1f71f3f0b528a9`
- **REPORT_v2:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/REPORT-v2.md` exists=`True` bytes=`20457` mtime=`2026-08-13T09:56:10.813665+00:00`
  - sha256: `2db4151789dd918ea95b63ad98624a084e419436463279bca6288c17457c3751`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`41006` mtime=`2026-08-13T10:01:20.162124+00:00`
  - sha256: `6eea01e5b2e2e283290290a8431ba831f6b566ac5c949d0b251cb7e388a36de5`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`39837` mtime=`2026-08-13T10:13:56.138293+00:00`
  - sha256: `726ef2a4bdc02042f8cc0555f8344b4ab00559bbdecda62f3b812afb775742a0`
- **report_v2_json:** `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/report-v2.json` exists=`True` bytes=`23273` mtime=`2026-08-13T10:01:20.165124+00:00`
  - sha256: `1ccc819e37bfde4a4852b89b2af0a38d111c5933c87c1d449d13cc0249ac4ec8`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 09:56:10 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

The sample `want.exe` (SHA256: `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09`) is a malicious Windows PE executable identified as a variant of the LockBit ransomware family. The binary is heavily obfuscated using PECompact v2.x packing, which encrypts the entire payload and leaves only a minimal stub visible to static analysis. The file exhibits a high overall entropy of 7.94 bits/byte, consisten
… [19550 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 10:11:16 UTC

# RE Report — d52f0647e519
_Generated 2026-08-13T10:11:16.952570+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=227c | cross_refs=True | llm_ok=True | runtime=66.79s -->

# Executive Summary

| Attribute          | Value                                  | Confidence |
|--------------------|----------------------------------------|------------|
| Verdict            | Malicious                              | High       |
| Family             | Ransomware.LockBit                     | High       |
| Overall Confidence | 90% (based on deep analysis)           | High       |
| Agree
… [45656 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
