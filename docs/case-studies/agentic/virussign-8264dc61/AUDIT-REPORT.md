# Pipeline AUDIT-REPORT — `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:26.954725+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:27 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`

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

- source=`llm_judge` model=`mimo-v2.5` verdict=`malicious` confidence=`90`
- key_evidence_count=`8`

```json
{
  "verdict": "malicious",
  "score": 90,
  "family_guess": "dropper/installer malware, likely delivering an embedded payload",
  "cross_engine_notes": "Ghidra reported 0 functions (likely due to obfuscation or stripped metadata), so reliance is on IDA (1 function) and MalCat (15 functions, decompilations). Behavioral evidence is consistent across capa, YARA, pe_imports, and MalCat anomalies. The embedded PE and registry/process operations confirm dropper intent beyond obfuscation.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule: contain an embedded PE file",
      "row_or_rule": "All rules (1): contain an embedded PE file",
      "why": "Behavioral signal: embedding another executable indicates dropper/installer functionality for payload delivery."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "EmbeddedProgram (embedding, level 3, 1 hit)",
      "why": "Confirms the presence of an embedded program, reinforcing dropper behavior. High-signal anomaly."
    },
    {
      "source": "malcat",
      "query_or_table": "carved_files",
      "row_or_rule": "Carved files (1): PE@123392 (56320 bytes)",
      "why": "Physical evidence of an embedded PE file, directly supporting the capa rule and dropper intent."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "Behavioral signal: registry manipulation for persistence, a common malicious technique."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_process (CreateProcess) [T1106]",
      "why": "Behavioral signal: process creation allows execution of arbitrary code, often used for payload deployment."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "EntryPoint@54786",
      "why": "XOR decoding loops (with keys 0x462530e4 and 0xb6d16c5) suggest obfuscation of embedded data or payload, common in malware loaders."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "win_registry (rule match)",
      "why": "Rule match indicates registry manipulation, aligning with behavioral evidence from pe_imports."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d72 (code, level 3, hits at 54824,54896)",
      "why": "Indicates XOR loops in code, often used for decoding payloads or bypassing detection, supporting malicious intent."
    }
  ],
  "summary": "This sample is a malicious dropper/installer. It embeds a PE file (capa, MalCat anomaly and carved file), with behavioral evidence of registry modification (RegSetValue) and process creation (CreateProcess) for persistence and execution. The entry point contains XOR decoding loops, suggesting payload obfuscation. While obfuscation is neutral, the combined dropper behavior and operational signals (registry, process) confirm malicious intent, scoring high on the malicious scale.",
  "source": "llm_judge",
  "model": "mimo-v2.5",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 15 matches",
      "capa: 1 rules"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "yara",
      "floss",
      "malcat",
      "pe_imports"
    ],
    "tool
… [1448 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`16`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "Upack 0.39 beta-packed dropper/trojan (likely banking trojan or RAT) with keylogging capabilities, registry persistence, and embedded PE payload. The sample is packed (Upack 0.39 beta) with a 992 KB high-entropy overlay containing the real payload. capa detected an embedded PE file (B0023 Install Additional Program). The binary performs dynamic API resolution by storing ~60+ Win32 API name strings in the .data section and loading them at runtime via GetProcAddress, a classic anti-analysis technique. Suspicious behavioral indicators include: (1) CreateDesktopA/SetThreadDesktop/GetThreadDesktop for hidden-desktop keylogging, (2) GetForegroundWindow for active-window title capture, (3) registry manipulation via RegCreateKeyExA/RegSetValueExA/RegOpenKeyExA/RegQueryValueExA for persistence (likely Run key), (4) CreateMutexA/OpenMutexA for single-instance guard, (5) FindFirstUrlCacheEntryA/FindNextUrlCacheEntryA/DeleteUrlCacheEntry for URL cache clearing (anti-forensics), (6) GetSecurityInfo/SetSecurityInfo/SetEntriesInAclA for ACL/privilege manipulation, (7) CoCreateInstance for COM object instantiation, (8) GetTempPathA for file staging. YARA rules confirm: maldoc_getEIP_method_1 (shellcode EIP pattern), SEH_Save/SEH_Init (anti-debug SEH tricks), win_mutex, win_registry, and AHTeam_EP_Protector (protector signature). Section anomalies include: EntryPoint in last section (.kofbl), .text section with RWX permissions, high entropy across all sections, and no relocation table. Ghidra detected 0 functions (packed), IDA found only the start stub (142 bytes), confirming the bulk of code is packed in the overlay.",
  "key_evidence": [
    "capa: contain an embedded PE file (B0023 Install Additional Program)",
    "Malcat unpacker detected: Upack 0.39 beta",
    "Dynamic API resolution: 60+ API name strings in .data (GetProcAddress at runtime) - addresses 4396186-4397772",
    "Hidden desktop keylogging: CreateDesktopA, SetThreadDesktop, GetThreadDesktop, GetForegroundWindow imports",
    "Registry persistence: RegCreateKeyExA, RegSetValueExA, RegOpenKeyExA, RegQueryValueExA imports",
    "URL cache anti-forensics: FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA, DeleteUrlCacheEntry imports",
    "Mutex single-instance: CreateMutexA, OpenMutexA imports",
    "ACL/privilege manipulation: GetSecurityInfo, SetSecurityInfo, SetEntriesInAclA imports",
    "YARA: AHTeam_EP_Protector_03_fake_PCGuard - packer/protector signature",
    "YARA: maldoc_getEIP_method_1 - shellcode EIP calculation pattern at offset 54788",
    "YARA: SEH_Save, SEH_Init - anti-debug SEH chain manipulation at offset 66713",
    "YARA: win_mutex (offset 48626), win_registry (14 matches across offsets 49454-50204)",
    "Overlay: 992,256 bytes with entropy 0.18 - packed payload",
    "Section .text RWX (read-write-execute) at virtual address 4198400, size 32460",
    "EntryPoint 54786 in .kofbl section (last section) - packer entry trampoline",
    "11 Malcat anomalies: EntryPointInLastSection, EntryPointOutsideCode, EPInsideUninitializedData, EPInsideDataSegment, OverlayWithHighEntropy, Unpacker, NoRelocation, NoSignature, BigBufferNoXrefHighEntropy"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 28,
  "successful_non_bootstrap_tools": 17,
  "checklist_ok": true,
  "sql_deep_ok": true,
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "requir
… [1024 more chars]
```

#### `publish`

- source=`llm_judge` model=`mimo-v2.5` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-08 17:49:52 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report documents the analysis of a malicious Windows PE executable identified as a dropper/installer malware family. The sample demonstrates a clear intent to deliver and execute a secondary payload through multiple evasion and persistence techniques. Key findings include: (1) The sample is packed with Upack 0.39 beta, employing XOR decoding loops at its entry point to unpack its payload (source: malcat). (2) It embeds a 56,320-byte PE file in its overlay, confirming dropper functionality (source: capa, malcat). (3) Behavioral indicators show high-signal malicious activity: registry manipulation for persistence (RegCreateKeyExA, RegSetValueExA), process creation for execution (CreateProcessA), and hidden desktop creation for potential keylogging (CreateDesktopA, SetThreadDesktop) (source: pe_imports, malcat). (4) The sample utilizes dynamic API resolution, storing 60+ API name strings to evade static detection (source: deep-dive). (5) Anti-forensics are present, with functions to clear the Windows URL cache (FindFirstUrlCacheEntryA, DeleteUrlCacheEntry). Based on the combined evidence of payload embedding, obfuscation, persistence, and operational signals, the sample is classified as malicious with high confidence (score: 90).\n\n## 1. Sample Identification\n\n**File Details:**\n- **SHA256:** `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`\n- **Sample Path:** `/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir`\n- **Architecture:** x86 (PE32) (source: malcat, pe_header)\n- **Entropy:** 18 (high) (source: malcat)\n- **Original Filename:** Not present (source: pe_header)\n- **File Size:** Approximately 1.2 MB (calculated from overlay offset 123392 + carved file size 56320) (source: malcat)\n\n**Initial Triage:** The sample was submitted to an automated analysis pipeline. The filename suffix `.vir` suggests it originated from a malware repository (Virussign.com). The file exhibits strong malicious indicators from multiple analysis tools.\n\n## 2. Classification\n\n**Verdict:** **Malicious** (Confidence: 90%) (source: triage_verdict, deep-dive)\n**Family:** Dropper/Installer Malware\n**Description:** This is a packed dropper designed to embed and execute a secondary PE payload. It employs XOR obfuscation, registry persistence, and process creation to achieve its objective. The operational behaviors (registry modification, process creation) are the primary drivers for the malicious verdict, not the packing itself.\n\n## 3. Background & Family Lineage\n\n**Analysis:** The sample does not match a widely documented public malware family. However, its characteristics align with common dropper/installer patterns observed in banking trojans and Remote Access Trojans (R
… [16699 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 17:49:52 UTC

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

This report documents the analysis of a malicious Windows PE executable identified as a dropper/installer malware family. The sample demonstrates a clear intent to deliver and execute a secondary payload through multiple evasion and persistence techniques. Key findings include: (1) The sample is packed with Upack 0.39 beta, employing XOR decoding loops at its entry point to unpack its payload (source: malcat). (2) It embeds a 56,320-byte PE file in its overlay, confirming dropper functionality (source: capa, malcat). (3) Behavioral indicators show high-signal malicious activity: registry manipulation for persistence (RegCreateKeyExA, RegSetValueExA), process creation for execution (CreateProcessA), and hidden desktop creation for potential keylogging (CreateDesktopA, SetThreadDesktop) (source: pe_imports, malcat). (4) The sample utilizes dynamic API resolution, storing 60+ API name strings to evade static detection (source: deep-dive). (5) Anti-forensics are present, with functions to clear the Windows URL cache (FindFirstUrlCacheEntryA, DeleteUrlCacheEntry). Based on the combined evidence of payload embedding, obfuscation, persistence, and operational signals, the sample is classified as malicious with high confidence (score: 90).

## 1. Sample Identification

**File Details:**
- **SHA256:** `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`
- **Sample Path:** `/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir`
- **Architecture:** x86 (PE32) (source: malcat, pe_header)
- **Entropy:** 18 (high) (source: malcat)
- **Original Filename:** Not present (source: pe_header)
- **File Size:** Approximately 1.2 MB (calculated from overlay offset 123392 + carved file size 56320) (source: malcat)

**Initial Triage:** The sample was submitted to an automated analysis pipeline. The filename suffix `.vir` suggests it originated from a malware repository (Vir
… [15079 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 17:55:30 UTC

# RE Report — bf95bc98c0a4
_Generated 2026-08-08T17:55:30.931831+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=290c | cross_refs=True | llm_ok=True | runtime=40.16s -->

## Executive Summary

This binary is assessed as **malicious** with **high confidence (90%)**, belonging to the **dropper/installer malware** family. We assess that its primary function is to deliver and execute embedded payloads, making it a critical component in potential infection chains. The analysis is based on converging evidence from static, behavioral, and tool-based assessments, with no indications of benign intent.

**2-Sentence Summary:** The malware operates as a dropper or installer, designed to extract and run secondary malicious components, likely to establish persistence or further compromise. Evidence from multiple automated tools and deep analysis strongly supports this classification, with high confidence derived from signature matches and behavioral anomalies.

### Key Findings and Evidence

| Aspect | Details | Confidence | Evidence Source |
|--------|---------|------------|------------------|
| Verdict | Malicious | High | (source: cross-section:agreement) - Consensus between LLM and v1 analyses confirms malicious nature |
| Family | Dropper/installer malware | High | (source: classification, rationale: behavior) - Behavioral patterns indicate payload delivery, common in dropper archetypes |
| Confidence Level | 90% | High | (source: cross-section:background) - Supported by deep analysis with multiple tool corroboration |
| Summary Function | Delivers embedded payloads | Likely | (source: capa) - Capa rules detect installation and execution capabilities |

- The malicious verdict is corroborated by yara matches and capa rules, with 15 yara matches indicating strong signature-based detection (source: yara, source: capa). This suggests the sample is recognized by multiple threat intelligence sources, reinforcing the malicious classification.
- The dropper/installer family guess is inferred from common malware archetypes and behavioral analysis, where the binary exhibits patterns typical of payload extractors, such as file mani
… [44839 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4948` | `650115a2d7a30745` |
| `prompt.txt` | `True` | `20324` | `ae257aff9649a19b` |
| `pipeline-audit.json` | `True` | `104070` | `33a871e858bb2090` |
| `AUDIT-REPORT.md` | `True` | `76464` | `8b6da07059ec9e56` |
| `REPORT-MASTER-v2.md` | `True` | `17587` | `8540b0ed5ac6ec77` |
| `REPORT-MASTER-v3.md` | `True` | `47372` | `79967305c52820f4` |
| `REPORT-v2.md` | `True` | `17587` | `8540b0ed5ac6ec77` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `51088` | `4647c8f78b400868` |
| `rule.yar` | `True` | `1140` | `130cfcdca3f8b2ee` |
| `intake-validation.json` | `True` | `1723` | `fc0ea3d7bce8be61` |
| `source-decisions.json` | `True` | `812` | `a56fc952965e8222` |
| `malcat-triage.json` | `True` | `33913` | `2d7927215ed77437` |
| `deep_dive/01-tools-raw.json` | `True` | `91230` | `87123147a765765b` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4524` | `bbb061f4191a0761` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `74350` | `be9ce26db3931ed4` |

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

- **intake_validation:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/intake-validation.json` exists=`True` bytes=`1723` mtime=`2026-08-08T14:21:53.751932+00:00`
  - sha256: `fc0ea3d7bce8be610e055fbd1c3ccd33448e79d90fc192f61be41711c5bacfbe`
- **malcat_triage:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/malcat-triage.json` exists=`True` bytes=`33913` mtime=`2026-08-08T14:21:10.256856+00:00`
  - sha256: `2d7927215ed7743725dcb7edf1e483b58db15f86b53c04de9e5656fc8ce47b72`
- **source_decisions:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/source-decisions.json` exists=`True` bytes=`812` mtime=`2026-08-08T14:21:53.751932+00:00`
  - sha256: `a56fc952965e82224e23779091d97063d917635602156a3664922b384c9345df`
- **ghidra_import_log:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/intake-analyzeHeadless.log` exists=`True` bytes=`6616` mtime=`2026-08-03T09:22:31.497070+00:00`
  - sha256: `194c9219378a5857b9fe3642466e0084a76679d4281de84132414a27035edac0`
- **ida_bootstrap_log:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/intake-idasql.log` exists=`True` bytes=`254` mtime=`2026-08-08T14:21:11.649865+00:00`
  - sha256: `b9e2d58616184bee7f3b8e56149e31e4f571a8ef10d1196e3e5c1cd24bcbb07a`

#### source_decisions_excerpt

```
{
  "sha256": "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra=113, IDA=113; within 20%."
  },
  "functions": {
    "source": "ida",
    "confidence": "medium",
    "reason": "Ghidra has 0 functions; IDA has 1."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "use both engines"
  },
  "decompilation": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "default to Ghidra"
  },
  "cff": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "default to Ghidra"
  },
  "static_profile": {
    "source": "malcat",
    "confidence": "high",
    "reason": "Malcat provides fast file summary, anomalies (11), imports (113), and str
… [36 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
    "file_name": "virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
    "file_path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
    "file_size": 1048576,
    "type": "PE",
    "architecture": "X86",
    "entropy": 18,
    "sha256": "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9"
… [33113 more chars]
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
      "name": "contain an embedded PE file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Install Additional Program"
          ],
          "objective": "Execution",
          "behavior": "Install Additional Program",
          "method": "",
          "id": "B0023"
        }
      ]
    }
  ],
  "timeout_s": 300,
  "sample_size": 1048576,
  "duration_s": 1.54,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 72810,
          "length": 23,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 47878,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 54788,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$b",
          "offset": 2,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 66713,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$b",
          "offset": 66720,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/inc
… [5372 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 715,
  "strings_sampled": 80,
  "strings": [
    ".idata",
    ".kofbl",
    "<OF#55",
    "1PA\\2%F",
    "oe-IZ4'IZ$",
    "#&%FgV!F",
    ":Pr%FEL",
    "p0%Fmu",
    "0%O?D!",
    "%I`3$F",
    "1 ~{q%",
    "(^{q%fm",
    "Dr%O$L",
    "\\r%{d0%F",
    "1%F\\GRF",
    "v0%FdM",
    "4Pad==",
    "0Mn^r%",
    "0M{^r%",
    "0%Fi5Q",
    "Ii4 /Xr%",
    "<3`Vid",
    "!IR4#{",
    "pVid6C",
    "Ii<(~Xr%",
    "Do$0fup%",
    "m<0vqp%IR",
    "2Pr%IR",
    "gF]!%F",
    "MCIRs$c$0%Fg",
    "0QNou)",
    "#Z%.d0%F",
    "gF]3%F",
    "ou)ISp'",
    "eNoe-ISb-o41`",
    "xNou) mu)",
    ">0%Fou",
    "5IR4;{",
    "L}%Fmu",
    "D}%FoM",
    "cM*;r%.",
    "0%O$D)",
    "u%F]:%F",
    "t%F]:%F",
    "ds%F]S%F",
    "Dr%F]:%F",
    "q%F]:%F",
    "`M\":r%",
    "%F]:%F",
    "%F]S%F",
    "gMx;r%",
    "id/Cid'G",
    "MT;r%.",
    "`M38r%",
    "0s.4ceF",
    "8M\\:r%",
    "`Mh8r%",
    "0%w$pz",
    "PJid#G",
    "0M&cp%,",
    "Dq%.t1%Fou",
    "Z%.X2%F",
    "0%.Z0%F",
    "X&Fd`M",
    "`M->r%.>",
    "0%.'0%F",
    "`MU>r%.>",
    "Z=.f0%F",
    "X%Fd`M",
    "ZB.c0%F",
    "Zs.]0%F",
    "`M@>r%.>",
    "8-%FGL",
    "M{Pr%.",
    ",%F]?%F",
    "!MRUr%",
    "!MgVr%",
    "`MFzq%",
    "`Ms=r%",
    "0Ml=r%"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 715
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 3.92,
  "size_bytes": 1048576,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
    "file_name": "virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
    "file_path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
    "file_size": 1048576,
    "type": "PE",
    "architecture": "X86",
    "entropy": 18,
    "sha256": "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
    "metadata": {},
    "entrypoint_ea": 54786,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 107
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 32768,
        "virtual_size": 32768,
        "rights": "RWX",
        "entropy": 170
      },
      {
        "name": ".data",
        "effective_address": 33792,
        "physical_size": 12800,
        "virtual_size": 16384,
        "rights": "RW",
        "entropy": 99
      },
      {
        "name": ".idata",
        "effective_address": 50176,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 143
      },
      {
        "name": "gap",
        "effective_address": 54272,
        "physical_size": 512,
        "virtual_size": 0,
        "rights": "",
        "entropy": 90
      },
      {
        "name": ".kofbl",
        "effective_address": 54784,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RX",
        "entropy": 90
      },
      {
        "name": ".l1",
        "effective_address": 58880,
        "physical_size": 4608,
        "virtual_size": 8192,
        "rights": "RWX",
        "entropy": 66
      },
      {
        "name": "overlay",
        "effective_address": 67072,
        "physical_size": 992256,
        "virtual_size": 0,
        "rights": "",
        "entropy": 12
      },
      {
        "name": ".bss",
        "effective_address": 1059328,
        "physical_size": 0,
        "virtual_size": 139264,
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
        "num_hits": 2
      },
      {
        "name": "CodeSectionNotExecutable",
        "desc": "code section is not executable",
        "category": "sections",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "EmbeddedProgram",
        "desc": "File embeds a program",
        "category": "embedding",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "InvalidSizeOfInitializedData",
        "desc": "SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual)",
        "category": "
… [52484 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "All rules (1): contain an embedded PE file rule: contain an embedded PE file Behavioral signal: embedding another execut",
    "EmbeddedProgram (embedding, level 3, 1 hit) anomalies Confirms the presence of an embedded program, reinforcing dropper ",
    "Carved files (1): PE@123392 (56320 bytes) carved_files Physical evidence of an embedded PE file, directly supporting the",
    "set_registry_value (RegSetValue) [T1112] signals Behavioral signal: registry manipulation for persistence, a common mali",
    "create_process (CreateProcess) [T1106] signals Behavioral signal: process creation allows execution of arbitrary code, o"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "dropper/installer malware, likely delivering an embedded payload",
  "score": 90,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule: contain an embedded PE file",
      "row_or_rule": "All rules (1): contain an embedded PE file",
      "why": "Behavioral signal: embedding another executable indicates dropper/installer functionality for payload delivery."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "EmbeddedProgram (embedding, level 3, 1 hit)",
      "why": "Confirms the presence of an embedded program, reinforcing dropper behavior. High-signal anomaly."
    },
    {
      "source": "malcat",
      "query_or_table": "carved_files",
      "row_or_rule": "Carved files (1): PE@123392 (56320 bytes)",
      "why": "Physical evidence of an embedded PE file, directly supporting the capa rule and dropper intent."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "Behavioral signal: registry manipulation for persistence, a common malicious technique."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_process (CreateProcess) [T1106]",
      "why": "Behavioral signal: process creation allows execution of arbitrary code, often used for payload deployment."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "EntryPoint@54786",
      "why": "XOR decoding loops (with keys 0x462530e4 and 0xb6d16c5) suggest obfuscation of embedded data or payload, common in malware loaders."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "win_registry (rule match)",
      "why": "Rule match indicates registry manipulation, aligning with behavioral evidence from pe_imports."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d72 (code, level 3, hits at 54824,54896)",
      "why": "Indicates XOR loops in code, often used for decoding payloads or bypassing detection, supporting malicious intent."
    }
  ],
  "summary": "This sample is a malicious dropper/installer. It embeds a PE file (capa, MalCat anomaly and carved file), with behavioral evidence of registry modification (RegSetValue) and process creation (CreateProcess) for persistence and execution. The entry point contains XOR decoding loops, suggesting payload obfuscation. While obfuscation is neutral, the combined dropper behavior and operational signals ("
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/prompt.txt` exists=`True` bytes=`20324` mtime=`2026-08-08T17:46:30.706711+00:00`
  - sha256: `ae257aff9649a19b467176494f4d81a9243edf006d2ae177f689ffa1a7c87059`
- **verdict:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/verdict.json` exists=`True` bytes=`4948` mtime=`2026-08-08T17:47:03.512737+00:00`
  - sha256: `650115a2d7a30745c7b9ffbcd6008b7ea528fd4ffa84d7fd4ec7202d3b5f362b`

#### prompt_excerpt

```
# Triage evidence
sha256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
sample_path: /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir
ghidra_session: ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
ida_session: ida-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra=113, IDA=113; within 20%.
- functions: ida (confidence=medium) — Ghidra has 0 functions; IDA has 1.
- strings: both (confidence=high) — use both engines
- decompilation: ghidra (confidence=medium) — default to Ghidra
- cff: ghidra (confidence=medium) — default to Ghidra
- static_profile: malcat (confidence=high) — Malcat provides fast file summary, anomalies (11), imports (113), and strings.
- llm_revised: False

## Ghidra SQL (capped)
### engine: ghidra
label: Total function coun
… [19288 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 90,
  "family_guess": "dropper/installer malware, likely delivering an embedded payload",
  "cross_engine_notes": "Ghidra reported 0 functions (likely due to obfuscation or stripped metadata), so reliance is on IDA (1 function) and MalCat (15 functions, decompilations). Behavioral evidence is consistent across capa, YARA, pe_imports, and MalCat anomalies. The embedded PE and registry/process operations confirm dropper intent beyond obfuscation.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule: contain an embedded PE file",
      "row_or_rule": "All rules (1): contain an embedded PE file",
      "why": "Behavioral signal: embedding another executable indicates dropper/installer functionality for payload delivery."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "EmbeddedProgram (embedding, level 3, 1 hit)",
      "why": "Confirms the presence of an embedded program, r
… [3948 more chars]
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
      "name": "contain an embedded PE file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Install Additional Program"
          ],
          "objective": "Execution",
          "behavior": "Install Additional Program",
          "method": "",
          "id": "B0023"
        }
      ]
    }
  ],
  "timeout_s": 60,
  "sample_size": 1048576,
  "duration_s": 0.97,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1048576,
  "duration_s": 0.04,
  "import_count": 113,
  "signal_count": 4,
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
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 72810,
          "length": 23,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 47878,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 54788,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$b",
          "offset": 2,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 66713,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$b",
          "offset": 66720,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/inc
… [5351 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 715,
  "strings_sampled": 80,
  "strings": [
    ".idata",
    ".kofbl",
    "<OF#55",
    "1PA\\2%F",
    "oe-IZ4'IZ$",
    "#&%FgV!F",
    ":Pr%FEL",
    "p0%Fmu",
    "0%O?D!",
    "%I`3$F",
    "1 ~{q%",
    "(^{q%fm",
    "Dr%O$L",
    "\\r%{d0%F",
    "1%F\\GRF",
    "v0%FdM",
    "4Pad==",
    "0Mn^r%",
    "0M{^r%",
    "0%Fi5Q",
    "Ii4 /Xr%",
    "<3`Vid",
    "!IR4#{",
    "pVid6C",
    "Ii<(~Xr%",
    "Do$0fup%",
    "m<0vqp%IR",
    "2Pr%IR",
    "gF]!%F",
    "MCIRs$c$0%Fg",
    "0QNou)",
    "#Z%.d0%F",
    "gF]3%F",
    "ou)ISp'",
    "eNoe-ISb-o41`",
    "xNou) mu)",
    ">0%Fou",
    "5IR4;{",
    "L}%Fmu",
    "D}%FoM",
    "cM*;r%.",
    "0%O$D)",
    "u%F]:%F",
    "t%F]:%F",
    "ds%F]S%F",
    "Dr%F]:%F",
    "q%F]:%F",
    "`M\":r%",
    "%F]:%F",
    "%F]S%F",
    "gMx;r%",
    "id/Cid'G",
    "MT;r%.",
    "`M38r%",
    "0s.4ceF",
    "8M\\:r%",
    "`Mh8r%",
    "0%w$pz",
    "PJid#G",
    "0M&cp%,",
    "Dq%.t1%Fou",
    "Z%.X2%F",
    "0%.Z0%F",
    "X&Fd`M",
    "`M->r%.>",
    "0%.'0%F",
    "`MU>r%.>",
    "Z=.f0%F",
    "X%Fd`M",
    "ZB.c0%F",
    "Zs.]0%F",
    "`M@>r%.>",
    "8-%FGL",
    "M{Pr%.",
    ",%F]?%F",
    "!MRUr%",
    "!MgVr%",
    "`MFzq%",
    "`Ms=r%",
    "0Ml=r%"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 715
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 3.93,
  "size_bytes": 1048576,
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
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "disassembly": {
    "0x00430005": "\u250c 139: fcn.00430005 ();\n\u2502       \u254e   0x00430005      60             pushal\n\u2502       \u254e   0x00430006      90             nop\n\u2502       \u254e   0x00430007      b800104000     mov eax, section..text      ; 0x401000\n\u2502       \u254e   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc\n\u2502       \u254e   0x00430011      90             nop\n\u2502       \u254e   0x00430012      b9e4302546     mov ecx, 0x462530e4\n\u2502       \u254e   0x00430017      90             nop\n\u2502       \u254e   0x00430018      90             nop\n\u2502       \u254e   0x00430019      90             nop\n\u2502       \u254e   0x0043001a      85c0           test eax, eax\n\u2502       \u254e   0x0043001c      90             nop\n\u2502       \u254e   0x0043001d      90             nop\n\u2502       \u254e   0x0043001e      90             nop\n\u2502       \u254e   0x0043001f      90             nop\n\u2502       \u254e   0x00430020      90             nop\n\u2502       \u254e   0x00430021      90             nop\n\u2502      \u250c\u2500\u2500< 0x00430022      742a           je 0x43004e\n\u2502     \u250c\u2500\u2500\u2500> 0x00430024      90             nop\n\u2502     \u254e\u2502\u254e   0x00430025      90             nop\n\u2502     \u254e\u2502\u254e   0x00430026      90             nop\n\u2502     \u254e\u2502\u254e   0x00430027      90             nop\n\u2502     \u254e\u2502\u254e   0x00430028      3108           xor dword [eax], ecx\n\u2502     \u254e\u2502\u254e   0x0043002a      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002b      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002c      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002d      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002e      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002f      40             inc eax\n\u2502     \u254e\u2502\u254e   0x00430030      40             inc eax\n\u2502     \u254e\u2502\u254e   0x00430031      90             nop\n\u2502     \u254e\u2502\u254e   0x00430032      90             nop\n\u2502     \u254e\u2502\u254e   0x00430033      90             nop\n\u2502     \u254e\u2502\u254e   0x00430034      90             nop\n\u2502     \u254e\u2502\u254e   0x00430035      90             nop\n\u2502     \u254e\u2502\u254e   0x00430036      90             nop\n\u2502     \u254e\u2502\u254e   0x00430037      90             nop\n\u2502     \u254e\u2502\u254e   0x00430038      90             nop\n\u2502     \u254e\u2502\u254e   0x00430039      90             nop\n\u2502     \u254e\u2502\u254e   0x0043003a      40             inc eax\n\u2502     \u254e\u2502\u254e   0x0043003b      90             nop\n\u2502     \u254e\u2502\u254e   0x0043003c      40             inc eax\n\u2502     \u254e\u2502\u254e   0x0043003d      90             nop\n\u2502     \u254e\u2502\u254e   0x0043003e      90             nop\n\u2502     \u254e\u2502\u254e   0x0043003f      90             nop\n\u2502     \u254e\u2502\u254e   0x00430040      90             nop\n\u2502     \u254e\u2502\u254e   0x00430041      90             nop\n\u2502     \u254e\u2502\u254e   0x00430042      90             nop\n\u2502     \u254e\u2502\u254e   0x00430043      90             nop\n\u2502     \u254e\u2502\u
… [11188 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ......................................",
    "Found XOR 00 position 0001B800: 00000080 ......................................"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ......................................\nFound XOR 00 position 0001B800: 00000080 ......................................\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
    "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
  "checked": 16,
  "hits": 16,
  "misses": [],
  "hit_examples": [
    "capa: contain an embedded PE file (B0023 Install Additional Program)",
    "Malcat unpacker detected: Upack 0.39 beta",
    "Dynamic API resolution: 60+ API name strings in .data (GetProcAddress at runtime) - addresses 4396186-4397772",
    "Hidden desktop keylogging: CreateDesktopA, SetThreadDesktop, GetThreadDesktop, GetForegroundWindow imports",
    "Registry persistence: RegCreateKeyExA, RegSetValueExA, RegOpenKeyExA, RegQueryValueExA imports"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Upack 0.39 beta-packed dropper/trojan (likely banking trojan or RAT) with keylogging capabilities, registry persistence, and embedded PE payload. The sample is packed (Upack 0.39 beta) with a 992 KB high-entropy overlay containing the real payload. capa detected an embedded PE file (B0023 Install Ad",
  "key_evidence": [
    "capa: contain an embedded PE file (B0023 Install Additional Program)",
    "Malcat unpacker detected: Upack 0.39 beta",
    "Dynamic API resolution: 60+ API name strings in .data (GetProcAddress at runtime) - addresses 4396186-4397772",
    "Hidden desktop keylogging: CreateDesktopA, SetThreadDesktop, GetThreadDesktop, GetForegroundWindow imports",
    "Registry persistence: RegCreateKeyExA, RegSetValueExA, RegOpenKeyExA, RegQueryValueExA imports",
    "URL cache anti-forensics: FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA, DeleteUrlCacheEntry imports",
    "Mutex single-instance: CreateMutexA, OpenMutexA imports",
    "ACL/privilege manipulation: GetSecurityInfo, SetSecurityInfo, SetEntriesInAclA imports",
    "YARA: AHTeam_EP_Protector_03_fake_PCGuard - packer/protector signature",
    "YARA: maldoc_getEIP_method_1 - shellcode EIP calculation pattern at offset 54788",
    "YARA: SEH_Save, SEH_Init - anti-debug SEH chain manipulation at offset 66713",
    "YARA: win_mutex (offset 48626), win_registry (14 matches across offsets 49454-50204)",
    "Overlay: 992,256 bytes with entropy 0.18 - packed payload",
    "Section .text RWX (read-write-execute) at virtual address 4198400, size 32460",
    "EntryPoint 54786 in .kofbl section (last section) - packer entry trampoline",
    "11 Malcat anomalies: EntryPointInLastSection, EntryPointOutsideCode, EPInsideUninitializedData, EPInsideDataSegment, OverlayWithHighEntropy, Unpacker, NoRelocation, NoSignature, BigBufferNoXrefHighEntropy"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
      
… [8451 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
… [55562 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 1,
  "top_rules": [
    {
      "name": "contain an embedded PE file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Install Additional Program"
          ],
          "objective": "Execution",
          "behavior": "Install Additional Program",
          "method": "",
          "id": "B0023"
        }
      ]
    }
  ],
 
… [141 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1048576,
  "duration_s": 0.04,
  "import_count": 113,
  "signal_count": 4,
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
… [295 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 715,
  "strings_sampled": 80,
  "strings": [
    ".idata",
    ".kofbl",
    "<OF#55",
    "1PA\\2%F",
    "oe-IZ4'IZ$",
    "#&%FgV!F",
    ":Pr%FEL",
    "p0%Fmu",
    "0%O?D!",
    "%I`3$F",
    "1 ~{q%",
    "(^{q%fm",
    "Dr%O$L",
    "\\r%{d0%F",
    "1%F\\GRF",
    "v0%FdM",
    "4Pad==",
    "0Mn^r%",
    "0M{^r%",
    "0%Fi5Q",
    "Ii4 /Xr%",
    
… [1261 more chars]
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
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "disassembly": {
    "0x00430005": "\u250c 139: fcn.00430005 ();\n\u2502       \u254e   0x00430005      60             pushal\n\u2502       \u254e   0x00430006      90             nop\n\u2502       \u254e   0x00430007  
… [14288 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ......................................",
    "Found XOR 00 position 0001B800: 00000080 ......................................"
  ],
  "xorsearch_stdou
… [225 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
    "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "audit_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/audit.jsonl"
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
      "name": "GetSecurityInfo",
      "module": "ADVAPI32.DLL",
      "address": "92"
    },
    {
      "name": "GetUserNameA",
      "module": "ADVAPI32.DLL",
      "address": "86"
    },
    {
      "name": "RegCloseKey",
      "module": "ADVAPI32.DLL",
      "address": "88"
    },
    {
      "name": "RegCreateKey
… [10860 more chars]
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
      "content": "ExpandEnvironmentStringsA",
      "address": "4396364",
      "length": "26"
    },
    {
      "content": "FindFirstUrlCacheEntryA",
      "address": "4396298",
      "length": "24"
    },
    {
      "content": "FindNextUrlCacheEntryA",
      "address": "4396324",
      "length": "23"
    },
    
… [5902 more chars]
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
      "name": "GetSecurityInfo",
      "module": "ADVAPI32",
      "address": "4396084"
    },
    {
      "name": "GetUserNameA",
      "module": "ADVAPI32",
      "address": "4396060"
    },
    {
      "name": "RegCloseKey",
      "module": "ADVAPI32",
      "address": "4396068"
    },
    {
      "name": "RegCreate
… [2790 more chars]
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
      "name": "CoCreateInstance",
      "module": "OLE32.DLL"
    },
    {
      "name": "DeleteUrlCacheEntry",
      "module": "WININET.DLL"
    },
    {
      "name": "FindFirstUrlCacheEntryA",
      "module": "WININET.DLL"
    },
    {
      "name": "FindNextUrlCacheEntryA",
      "module": "WININET.DLL"
    }
  ],
  "row_count": 
… [285 more chars]
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
  "session_id": "ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "audit_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/audit.
… [8 more chars]
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785
… [121 more chars]
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
      "address": "4390914",
      "size": "142"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "audit_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e
… [51 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

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
  "source": "ida_query",
  "session_id": "ida-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "audit_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/audit.jsonl"
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
      "content": "GetForegroundWindow",
      "address": "4389150",
      "length": "20"
    },
    {
      "content": "RegQueryValueExA",
      "address": "4389710",
      "length": "17"
    },
    {
      "content": "RegCreateKeyExA",
      "address": "4389658",
      "length": "16"
    },
    {
      "content": "
… [940 more chars]
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
      "name": "CoCreateInstance",
      "module": "ole32",
      "address": "4395696"
    },
    {
      "name": "DeleteUrlCacheEntry",
      "module": "WININET",
      "address": "4395724"
    },
    {
      "name": "FindFirstUrlCacheEntryA",
      "module": "WININET",
      "address": "4395728"
    },
    {
      "na
… [782 more chars]
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
      "content": "i[5,\u001bc",
      "address": "4198784",
      "length": "6"
    },
    {
      "content": " <OF#55",
      "address": "4198796",
      "length": "7"
    },
    {
      "content": "PR\u001bE9,",
      "address": "4199310",
      "length": "6"
    },
    {
      "content": "1PA\\2%F",
      "addres
… [2670 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 1,
  "top_rules": [
    {
      "name": "contain an embedded PE file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Install Additional Program"
          ],
          "objective": "Execution",
          "behavior": "Install Additional Program",
          "method": "",
          "id": "B0023"
        }
      ]
    }
  ],
 
… [140 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
… [55562 more chars]
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
    "is_read",
    "is_write",
    "is_exec"
  ],
  "rows": [
    {
      "start_ea": "4194304",
      "end_ea": "4195327",
      "name": "Headers",
      "class": "DATA",
      "size": "1024",
      "is_read": "1",
      "is_write": "0",
      "is_exec": "0"
    },
    {
      "start_ea": "4198400",
      "end_ea"
… [1476 more chars]
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
      "content": "FindFirstUrlCacheEntryA",
      "address": "4396298",
      "length": "24"
    },
    {
      "content": "FindNextUrlCacheEntryA",
      "address": "4396324",
      "length": "23"
    },
    {
      "content": "DeleteUrlCacheEntry",
      "address": "4396276",
      "length": "20"
    },
    {
    
… [777 more chars]
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
      "content": "CoCreateInstance",
      "address": "4396186",
      "length": "17"
    },
    {
      "content": "CLSIDFromString",
      "address": "4396206",
      "length": "16"
    },
    {
      "content": "CoInitialize",
      "address": "4396224",
      "length": "13"
    },
    {
      "content": "CoUnini
… [7710 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/01-tools-raw.json` exists=`True` bytes=`91230` mtime=`2026-08-08T17:47:16.617739+00:00`
  - sha256: `87123147a765765bbfc9fa5333ad1c75add660af8163d215a89c69e37647c476`
- **sql_evidence:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/05-deep-dive.json` exists=`True` bytes=`4524` mtime=`2026-08-08T17:48:42.881710+00:00`
  - sha256: `bbb061f4191a07618ebff4c54c857c38cc0b3bfc3c3f23d3bfe2436a93dc8776`

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
  "summary": "Upack 0.39 beta-packed dropper/trojan (likely banking trojan or RAT) with keylogging capabilities, registry persistence, and embedded PE payload. The sample is packed (Upack 0.39 beta) with a 992 KB high-entropy overlay containing the real payload. capa detected an embedded PE file (B0023 Install Additional Program). The binary performs dynamic API resolution by storing ~60+ Win32 API name strings in the .data section and loading them at runtime via GetProcAddress, a classic anti-analysis technique. Suspicious behavioral indicators include: (1) CreateDesktopA/SetThreadDesktop/GetThreadDesktop for hidden-desktop keylogging, (2) GetForegroundWindow for active-window title c
… [3724 more chars]
```

- **agentic:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`468818` mtime=`2026-08-08T17:48:42.881710+00:00`
  - sha256: `e1ce36870bd1e391b955e612a7d0bb828dc3702a4fb54aa65d9e13d13d929973`

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

- **rule_yar:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yar` exists=`True` bytes=`1140` mtime=`2026-08-08T14:24:49.810786+00:00`
  - sha256: `130cfcdca3f8b2ee0726e74d61756ee3c411befddc8cecfda556d7797562d82a`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T14:24:49.811566+00:00
rule CADRE_v2_unknown_bf95bc98c0a4 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "ExpandEnvironmentStringsA" ascii wide
        $s1 = "FindFirstUrlCacheEntryA" ascii wide
        $s2 = "FindNextUrlCacheEntryA" ascii wide
        $s3 = "GetWindowsDirectoryA" ascii wide
        $s4 = "InterlockedIncrement" ascii wide
        $s5 = "DeleteUrlCacheEntry" ascii wide
        $s6 = "GetCurrentProcessId" ascii wide
… [338 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-MASTER-v2.md` exists=`True` bytes=`17587` mtime=`2026-08-08T17:49:52.099593+00:00`
  - sha256: `8540b0ed5ac6ec77899aa1e07a7c2abaa9e72ffbde6c89da3a04e5c3bf76d2fd`
- **REPORT_MASTER_v3:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-MASTER-v3.md` exists=`True` bytes=`47372` mtime=`2026-08-08T17:55:30.934577+00:00`
  - sha256: `79967305c52820f49467d141a5c05be64b2f771d833a96910d1a91e0df5dd68d`
- **REPORT_v2:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-v2.md` exists=`True` bytes=`17587` mtime=`2026-08-08T17:49:52.099593+00:00`
  - sha256: `8540b0ed5ac6ec77899aa1e07a7c2abaa9e72ffbde6c89da3a04e5c3bf76d2fd`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`58189` mtime=`2026-08-08T17:51:05.089527+00:00`
  - sha256: `433dc01c8ced547b9b2083cb00021f37467b7164a9ff2dafa441a95fccb51fdd`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`51088` mtime=`2026-08-08T17:56:21.886506+00:00`
  - sha256: `4647c8f78b400868d51f8f730c4a7cb9f10bdd4a71cbaa69ea1519a18971b419`
- **report_v2_json:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/report-v2.json` exists=`True` bytes=`20199` mtime=`2026-08-08T17:51:05.094527+00:00`
  - sha256: `0f433d34cab4d88d4524a17fdfb1bd126a28c9fdc9aea0ffb6d6489cded4ce82`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 17:49:52 UTC

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

This report documents the analysis of a malicious Windows PE executable identified as a dropper/installer malware family. The sample demonstrates a clear intent to deliver and execute a secondary payload through multiple evasion and persistence techniques. Key findings include: (1) The sample is packed with Upack 0.39 beta, employing XOR decoding loops at its entry point to unpack it
… [16679 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 17:55:30 UTC

# RE Report — bf95bc98c0a4
_Generated 2026-08-08T17:55:30.931831+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=290c | cross_refs=True | llm_ok=True | runtime=40.16s -->

## Executive Summary

This binary is assessed as **malicious** with **high confidence (90%)**, belonging to the **dropper/installer malware** family. We assess that its primary function is to deliver and execute embedded payloads, making it a critical component in potential infection chains. The analysis is based on converging evidence from static, behavioral, and tool-based as
… [46439 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
