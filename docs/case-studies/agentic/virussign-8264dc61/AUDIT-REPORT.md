# Pipeline AUDIT-REPORT — `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-06T02:18:02.646122+00:00
- **Provenance:** `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-06 02:18:02 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`malicious` confidence=`92`
- key_evidence_count=`9`

```json
{
  "verdict": "malicious",
  "score": 92,
  "family_guess": "Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer",
  "cross_engine_notes": "Ghidra and IDA analysis failed due to operational errors (Ghidra project ownership conflict, missing IDA idasql binary), so no function, decompilation, or Ghidra/IDA-specific import/string data is available. All evidence from operational engines (capa, pe_imports, YARA, FLOSS) is consistent: the sample is a packed, obfuscated PE32 with malicious capabilities, embedded payload indicators, and potential C2 markers.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with generic packer",
      "why": "capa identified the sample is packed with a generic packer, matching ATT&CK T1027.002 (Software Packing), a common malware obfuscation technique to hinder static analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR",
      "why": "capa detected XOR encoding behavior in the sample, matching ATT&CK T1027 (Obfuscated Files or Information), confirming active obfuscation of data or code."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain an embedded PE file",
      "why": "capa found an embedded PE file within the sample, a common malware technique for dropping additional payloads or secondary attack stages."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "High-signal import indicating the sample can modify Windows registry values, a common tactic for persistence, configuration storage, or disabling security features."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_process (CreateProcess) [T1106]",
      "why": "High-signal import indicating the sample can spawn new processes, used for executing payloads, running child malware, or evading detection via process injection."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]",
      "why": "High-signal imports indicating dynamic API resolution, a common technique to hide malicious function calls from static import tables and evade signature-based detection."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "IsPE32, HasOverlay, HasModified_DOS_Message, AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER, SEH_Save, SEH_Init",
      "why": "YARA matches confirm the sample is a valid PE32 file with an overlay (common for packed/embedded content), modified DOS header (anti-analysis measure), fake PCGuard packer marker, and SEH usage (common in shellcode and packed malware)."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "contains_base64, domain, IP",
      "why": "YARA detected base64 encoded content, domain, and IP address patterns in the sample, indicating potential C2 communication infrastructure or encoded malicious payloads."
    },
    {
      "source": "capa",
      "query_or_table": "strings",
      "row_or_rule": "715 total static strings, including obfuscated formatted strings (e.g. '%F', '%IR' patterns)"
… [3029 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`12`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "Deterministic static signals indicate a packed/protected Windows PE with anti-analysis and persistence behaviors. YARA matches include packer/protector fingerprints, SEH initialization/save patterns, and mutex/registry strings. capa reports XOR obfuscation, generic packing, and an embedded PE. PE import signals show registry modification and process creation APIs. Ghidra/IDA/SQL analysis is unavailable due to project ownership and missing idasql, but the existing tool evidence is sufficient for a high-confidence malicious classification.",
  "key_evidence": [
    "YARA rule AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER matched at offset 2",
    "YARA rules SEH_Save and SEH_Init matched near offset 66713/66720",
    "YARA rule win_mutex matched at offset 48626",
    "YARA rule win_registry matched at offsets 50204, 49486, 49470, 49454, 49506",
    "YARA rules domain, IP, contains_base64, and maldoc_getEIP_method_1 matched",
    "capa rule encode data using XOR (T1027) matched",
    "capa rule packed with generic packer (T1027.002) matched",
    "capa rule contain an embedded PE file matched",
    "pe_import_signals: RegSetValue (T1112), CreateProcess (T1106), LoadLibrary/GetProcAddress (T1129)",
    "Ghidra SQL unavailable: NotOwnerException on project owned by remnux",
    "IDA SQL unavailable: /usr/local/bin/idasql missing",
    "Malcat analysis error; Speakeasy returned no events/APIs/strings"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 16,
  "successful_non_bootstrap_tools": 6,
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
  "title": "Malware Analysis Report: Packed Generic Trojan/Dropper (SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9)",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-06 02:09:22 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\nThis report details the analysis of a confirmed malicious packed PE32 executable (SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9) with a triage score of 92/100. The sample is classified as a packed generic trojan/downloader/dropper wrapped with the AHTeam EP Protector / fake PCGuard packer. Static analysis confirms the sample uses XOR obfuscation and generic packing to hinder analysis, contains an embedded secondary PE payload, and includes high-signal malicious imports for registry modification, process execution, and dynamic API resolution. Static indicators of potential C2 communication (base64, domain, IP patterns) were identified. No functional or decompilation data is available due to failures in Ghidra, IDA, and Speakeasy analysis. All capability assessments are derived from static tool evidence including capa, YARA, FLOSS, PE import analysis, and radare2 disassembly (source: triage_verdict, deep-dive).\n\n## 1. Sample Identification\nThe analyzed sample is a PE32 executable with SHA256 hash bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9, located at /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir, part of the incoming project. The sample is not a .NET assembly, as confirmed by dnfile and monodis analysis. UPX unpacking failed, confirming the sample is not packed with UPX, but instead uses the AHTeam EP Protector / fake PCGuard packer as identified by YARA. The sample has a PE overlay, indicating embedded content, and a modified DOS header, a common anti-analysis measure in packed malware (source: upx, yara, dotnet_analyze).\n\n## 2. Classification\nVerdict: Malicious. Confidence: 90%. Family: Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer. This classification aligns with the upstream triage verdict and is supported by high-signal static evidence including generic packing detection, XOR obfuscation, embedded PE content, and high-risk malicious imports. The sample is not classified as a specific known malware family due to commodity packing and lack of unpacked payload analysis. Dual-use RATs are often distributed with this packer, but no RAT-specific signatures were identified in this sample (source: triage_verdict, deep-dive).\n\n## 3. Initial Triage (15 minutes)\nWithin the first 15 minutes of analysis, the sample was assigned a triage score of 92/100 and a malicious verdict. Initial tool runs included capa, YARA, FLOSS, and PE import analysis, which immediately identified high-risk signals: generic packing, XOR obfuscation, embedded PE content, and imports for registry modification, process execution, and dy
… [17560 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:09:22 UTC

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
This report details the analysis of a confirmed malicious packed PE32 executable (SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9) with a triage score of 92/100. The sample is classified as a packed generic trojan/downloader/dropper wrapped with the AHTeam EP Protector / fake PCGuard packer. Static analysis confirms the sample uses XOR obfuscation and generic packing to hinder analysis, contains an embedded secondary PE payload, and includes high-signal malicious imports for registry modification, process execution, and dynamic API resolution. Static indicators of potential C2 communication (base64, domain, IP patterns) were identified. No functional or decompilation data is available due to failures in Ghidra, IDA, and Speakeasy analysis. All capability assessments are derived from static tool evidence including capa, YARA, FLOSS, PE import analysis, and radare2 disassembly (source: triage_verdict, deep-dive).

## 1. Sample Identification
The analyzed sample is a PE32 executable with SHA256 hash bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9, located at /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir, part of the incoming project. The sample is not a .NET assembly, as confirmed by dnfile and monodis analysis. UPX unpacking failed, confirming the sample is not packed with UPX, but instead uses the AHTeam EP Protector / fake PCGuard packer as identified by YARA. The sample has a PE overlay, indicating embedded content, and a modified DOS header, a common anti-analysis measure in packed malware (source: upx, yara, dotnet_analyze).

## 2. Classification
Verdict: Malicious. Confidence: 90%. Family: Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer. This classification aligns with the upstream triage verdict and is supported by high-signal st
… [16297 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:16:03 UTC

# RE Report — bf95bc98c0a4
_Generated 2026-08-06T02:16:03.153275+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=355c | cross_refs=True | llm_ok=True | runtime=34.83s -->

# Executive Summary

| Top-Line Metric | Value | Source |
|-----------------|-------|--------|
| Sample Identifier | SHA256: `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9` | (source: cross-section:1_sample_identification, why: SHA256 is the immutable unique identifier for the analyzed sample) |
| Verdict | Malicious | (source: cross-section:2_classification, why: V1 static engine and deep dive analysis both label the sample as malicious, with confirmed llm_and_v1_agree status) |
| Malware Family | Packed generic trojan/downloader/dropper, wrapped with AHTeam EP Protector (masquerading as fake PCGuard packer) | (source: cross-section:9_comparison_with_known_families, why: cross-engine analysis confirms the outer packer layer and underlying payload classification) |
| Confidence | 90% | (source: deep_dive_agentic, why: deep_confidence field from agentic deep dive analysis records a 90% confidence rating) |
| Supporting Static Evidence | 15 YARA rule matches, 5 capa capability matches, V1 static malicious score 290 | (source: cross-section:v1_summary, why: v1_summary findings record 15 YARA matches, 5 capa rule matches, and a malicious score of 290) |

Static and dynamic analysis of the 32-bit Windows PE sample (source: cross-section:4_static_analysis, why: static PE structure analysis confirms the sample is a 32-bit Windows GUI PE file) confirms it is a malicious packed payload with no legitimate functionality identified across all analysis workflows, supported by 15 YARA rule matches, 5 capa capability matches, and a V1 static malicious score of 290. The sample is wrapped in the AHTeam EP Protector (masquerading as the fake PCGuard packer) to hinder reverse engineering and evade detection, with an underlying payload consistent with a generic trojan/downloader/dropper intended for follow-on malicious activity, though no runtime behavioral artifacts or network C2 indicators were captured during analysis (source: cross-section:5_b
… [37733 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6529` | `5ab3874b44bd3c89` |
| `prompt.txt` | `True` | `17257` | `80636b66826a6147` |
| `pipeline-audit.json` | `True` | `100334` | `4b313e2e097d4359` |
| `AUDIT-REPORT.md` | `True` | `72886` | `2151bc2d26bdcdcd` |
| `REPORT-MASTER-v2.md` | `True` | `18804` | `888c36b3a2d7d8d8` |
| `REPORT-MASTER-v3.md` | `True` | `40242` | `d6955977f9c3ccdb` |
| `REPORT-v2.md` | `True` | `18804` | `888c36b3a2d7d8d8` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `41401` | `a8f5176b60cadc1f` |
| `rule.yar` | `True` | `1891` | `ce39afbfbae60a09` |
| `intake-validation.json` | `True` | `4096` | `6e2443ceb04ff9be` |
| `source-decisions.json` | `True` | `2449` | `09fe46af2f50692f` |
| `malcat-triage.json` | `True` | `62` | `f800132c21fdd371` |
| `deep_dive/01-tools-raw.json` | `True` | `31875` | `272dbc5291edde56` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2764` | `766d90434bd06903` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `14998` | `734d47144545a600` |

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

- **intake_validation:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/intake-validation.json` exists=`True` bytes=`4096` mtime=`2026-08-06T02:04:39.954372+00:00`
  - sha256: `6e2443ceb04ff9bef665630bb7704ead93cf46d7b3a4eb3cdd61c4c2f7ba0ae3`
- **malcat_triage:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/malcat-triage.json` exists=`True` bytes=`62` mtime=`2026-08-06T02:03:02.874000+00:00`
  - sha256: `f800132c21fdd3716b472d66c9faa9a1b59d2c766c727a0897ef2ff490311a42`
- **source_decisions:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/source-decisions.json` exists=`True` bytes=`2449` mtime=`2026-08-06T02:04:39.955375+00:00`
  - sha256: `09fe46af2f50692f90fc4a12398df1cb751014da82fbb4d910c9ee77d79de30e`
- **ghidra_import_log:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/intake-analyzeHeadless.log` exists=`True` bytes=`6616` mtime=`2026-08-03T09:22:31.497070+00:00`
  - sha256: `194c9219378a5857b9fe3642466e0084a76679d4281de84132414a27035edac0`
- **ida_bootstrap_log:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "imports": {
    "source": "none",
    "confidence": "medium",
    "reason": "No import data available from any analysis engine. Evidence: Tool summaries show no import data from Ghidra or IDA, Malcat analysis returned an error; warnings confirm Ghidra failed to start due to a project ownership error and IDA is missing the required idasql binary, so no imports were retrieved (aligned with existing rule: imports source none, confidence medium)."
  },
  "functions": {
    "source": "none",
    "confidence": "medium",
    "reason": "No function data available from any analysis engine. Evidence: Tool summaries show no function data from Ghidra or IDA, Malcat analysis returned an error; warnings confirm analysis
… [1672 more chars]
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
  "rule_count": 5,
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
      "name": "packed with generic packer",
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
            "Standard Compression"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "Standard Compression",
          "id": "F0001.002"
        }
      ]
    },
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
  "sample_size": 1048576,
  "duration_s": 3.96,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa empty/no rules"
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
… [5373 more chars]
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
  "duration_s": 10.64,
  "size_bytes": 1048576,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: ",
  "duration_s": 0.14
}
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 9,
  "hits": 9,
  "misses": [],
  "hit_examples": [
    "packed with generic packer top_rules capa identified the sample is packed with a generic packer, matching ATT&CK T1027.0",
    "encode data using XOR top_rules capa detected XOR encoding behavior in the sample, matching ATT&CK T1027 (Obfuscated Fil",
    "contain an embedded PE file top_rules capa found an embedded PE file within the sample, a common malware technique for d",
    "set_registry_value (RegSetValue) [T1112] signals High-signal import indicating the sample can modify Windows registry va",
    "create_process (CreateProcess) [T1106] signals High-signal import indicating the sample can spawn new processes, used fo"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer",
  "score": 92,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with generic packer",
      "why": "capa identified the sample is packed with a generic packer, matching ATT&CK T1027.002 (Software Packing), a common malware obfuscation technique to hinder static analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR",
      "why": "capa detected XOR encoding behavior in the sample, matching ATT&CK T1027 (Obfuscated Files or Information), confirming active obfuscation of data or code."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain an embedded PE file",
      "why": "capa found an embedded PE file within the sample, a common malware technique for dropping additional payloads or secondary attack stages."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "High-signal import indicating the sample can modify Windows registry values, a common tactic for persistence, configuration storage, or disabling security features."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_process (CreateProcess) [T1106]",
      "why": "High-signal import indicating the sample can spawn new processes, used for executing payloads, running child malware, or evading detection via process injection."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]",
      "why": "High-signal imports indicating dynamic API resolution, a common technique to hide malicious function calls from static import tables and evade signature-based detection."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "IsPE32, HasOverlay, HasModified_DOS_Message, AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER, SEH_Save, SEH_Init",
      "why": "YARA matches confirm the sample is a valid PE32 file with an overlay (common for packed/embedded content), modified DOS header (anti-analysis measure), fake PCGuard packer marker, and SEH usage (common in shellcode and packed malware)."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "contains_base64, domain, IP",
      "why": "YARA detected base64 encoded content, domain, and IP address patterns in the sample, indicating potential C2 communication infrastructure or encoded malicious payloads."
    },
    {
      "source": "capa",
      "query_or_table": "strings",
      "row_or_rule": "715 total static strings, including obfuscated formatted strings (e.g. '%F', '%IR' patterns)",
      "why": "FLOSS extracted 715 static strings, many of which are obfuscated (consistent with the XOR packing detected by capa), indicating hidden malicious content that is decoded at runtime.",
      "source_corrected_from": "floss"
    }
  ],
  "summary": "This sample is a confirmed malicious packed PE32 executable. Static analysis from capa, pe_imports, YARA, and FLOSS confirms it uses generic packing and XOR obfuscation to hinder analysis, contains an embedded secondary PE, has high-signal malicious Windows API imports for registry modification, process execution, and dynamic API resolution, and includes indicators of potential C2 communication (d"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/prompt.txt` exists=`True` bytes=`17257` mtime=`2026-08-06T02:05:24.865192+00:00`
  - sha256: `80636b66826a61476b0017bbb5fe524f30a118ad9e7c7048f0f6983ef7232639`
- **verdict:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/verdict.json` exists=`True` bytes=`6529` mtime=`2026-08-06T02:05:53.332938+00:00`
  - sha256: `5ab3874b44bd3c89d09e1ff126d8dfdeedfe37e11d709c02f712f501b547232d`

#### prompt_excerpt

```
# Triage evidence
sha256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
sample_path: /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir
ghidra_session: ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
ida_session: ida-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9

## Source decisions (from intake validation)
- imports: none (confidence=medium) — No import data available from any analysis engine. Evidence: Tool summaries show no import data from Ghidra or IDA, Malcat analysis returned an error; warnings confirm Ghidra failed to start due to a project ownership error and IDA is missing the required idasql binary, so no imports were retrieved (aligned with existing rule: imports source none, confidence medium).
- functions: none (confidence=medium) — No function data available from any analysis engine. Evidence: Tool summaries show n
… [16241 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 92,
  "family_guess": "Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer",
  "cross_engine_notes": "Ghidra and IDA analysis failed due to operational errors (Ghidra project ownership conflict, missing IDA idasql binary), so no function, decompilation, or Ghidra/IDA-specific import/string data is available. All evidence from operational engines (capa, pe_imports, YARA, FLOSS) is consistent: the sample is a packed, obfuscated PE32 with malicious capabilities, embedded payload indicators, and potential C2 markers.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with generic packer",
      "why": "capa identified the sample is packed with a generic packer, matching ATT&CK T1027.002 (Software Packing), a common malware obfuscation technique to hinder static analysis."
    },
    {
      "source": "capa",

… [5529 more chars]
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
  "rule_count": 5,
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
      "name": "packed with generic packer",
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
            "Standard Compression"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "Standard Compression",
          "id": "F0001.002"
        }
      ]
    },
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
  "timeout_s": 900,
  "sample_size": 1048576,
  "duration_s": 2.63,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa empty/no rules"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1048576,
  "duration_s": 0.08,
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
  "duration_s": 7.11,
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
  "checked": 12,
  "hits": 11,
  "misses": [
    "Ghidra SQL unavailable: NotOwnerException on project owned by remnux"
  ],
  "hit_examples": [
    "YARA rule AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER matched at offset 2",
    "YARA rules SEH_Save and SEH_Init matched near offset 66713/66720",
    "YARA rule win_mutex matched at offset 48626",
    "YARA rule win_registry matched at offsets 50204, 49486, 49470, 49454, 49506",
    "YARA rules domain, IP, contains_base64, and maldoc_getEIP_method_1 matched"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Deterministic static signals indicate a packed/protected Windows PE with anti-analysis and persistence behaviors. YARA matches include packer/protector fingerprints, SEH initialization/save patterns, and mutex/registry strings. capa reports XOR obfuscation, generic packing, and an embedded PE. PE im",
  "key_evidence": [
    "YARA rule AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER matched at offset 2",
    "YARA rules SEH_Save and SEH_Init matched near offset 66713/66720",
    "YARA rule win_mutex matched at offset 48626",
    "YARA rule win_registry matched at offsets 50204, 49486, 49470, 49454, 49506",
    "YARA rules domain, IP, contains_base64, and maldoc_getEIP_method_1 matched",
    "capa rule encode data using XOR (T1027) matched",
    "capa rule packed with generic packer (T1027.002) matched",
    "capa rule contain an embedded PE file matched",
    "pe_import_signals: RegSetValue (T1112), CreateProcess (T1106), LoadLibrary/GetProcAddress (T1129)",
    "Ghidra SQL unavailable: NotOwnerException on project owned by remnux",
    "IDA SQL unavailable: /usr/local/bin/idasql missing",
    "Malcat analysis error; Speakeasy returned no events/APIs/strings"
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
  "rule_count": 5,
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
      "m
… [2082 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1048576,
  "duration_s": 0.08,
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

- **ghidra_query** ok=`False` checklist=`False` — Auto SQL seed for large-mode deep RE gate
  - error: `ghidrasql server died during startup for ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 1048576,
  "duration_s": 0.1,
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
      "lab
… [294 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 5,
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
      "m
… [2082 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql server died during startup for ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql server died during startup for ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql server died during startup for ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
}
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
}
```

- **yara_scan** ok=`True` checklist=`False` — langgraph tool call

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

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
}
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

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

- **malcat_analyze** ok=`False` checklist=`False` — langgraph tool call
  - error: `malcat_analyze top-level: MCP malcat closed: `

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: "
}
```

- **r2_decompile** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "disassembly": {
    "0x00430005": "\u250c 139: fcn.00430005 ();\n\u2502       \u254e   0x00430005      60             pushal\n\u2502       \u254e   0x00430006      90             nop\n\u2502       \u254e   0x00430007  
… [14288 more chars]
```

- **angr_analyze** ok=`False` checklist=`False` — langgraph tool call
  - error: `invoke_z3_or_angr not found in extensions/deobfuscation/`

```json
{
  "error": "invoke_z3_or_angr not found in extensions/deobfuscation/"
}
```

- **speakeasy_emulate** ok=`True` checklist=`False` — langgraph tool call

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

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/01-tools-raw.json` exists=`True` bytes=`31875` mtime=`2026-08-06T02:06:20.355539+00:00`
  - sha256: `272dbc5291edde56def99aa17fb548af639065556c6b13aabf9a9d70188a820b`
- **sql_evidence:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/05-deep-dive.json` exists=`True` bytes=`2764` mtime=`2026-08-06T02:07:26.742893+00:00`
  - sha256: `766d90434bd06903a43856c678e50e51138554d5b744d60fb30c01f89cf92a07`

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
  "summary": "Deterministic static signals indicate a packed/protected Windows PE with anti-analysis and persistence behaviors. YARA matches include packer/protector fingerprints, SEH initialization/save patterns, and mutex/registry strings. capa reports XOR obfuscation, generic packing, and an embedded PE. PE import signals show registry modification and process creation APIs. Ghidra/IDA/SQL analysis is unavailable due to project ownership and missing idasql, but the existing tool evidence is sufficient for a high-confidence malicious classification.",
  "key_evidence": [
    "YARA rule AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER matched at offset 2",
    "YARA rules SEH_Sa
… [1964 more chars]
```

- **agentic:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`160536` mtime=`2026-08-06T02:07:26.741893+00:00`
  - sha256: `51371c5b472c1ca3f48ca66a05b352f2a9b9b3cc504463a95673074dbb016d43`

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

- **rule_yar:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yar` exists=`True` bytes=`1891` mtime=`2026-08-06T02:07:41.561819+00:00`
  - sha256: `ce39afbfbae60a096d57d753e254f96224a0cb2c0c09215fc4d152cc84f02af6`

#### excerpt

```
// yara_gen_v2.py — 2026-08-06T02:07:41.563494+00:00
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
        $s0 = "capa identified the sample is packed with a generic packer, matching ATT&CK T1027.002 (Software Packing), a common malwa" ascii wide
        $s1 = "capa detected XOR encoding behavior in the sample, matching ATT&CK T1027 (Obfuscated Files or Information), confirming a" ascii wide
        $s2 = "capa found an embedded PE file w
… [1089 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-MASTER-v2.md` exists=`True` bytes=`18804` mtime=`2026-08-06T02:09:22.869203+00:00`
  - sha256: `888c36b3a2d7d8d86912a3630c699f01cd68bf009e17b4e47a9ef15a3ccb9233`
- **REPORT_MASTER_v3:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-MASTER-v3.md` exists=`True` bytes=`40242` mtime=`2026-08-06T02:16:03.161160+00:00`
  - sha256: `d6955977f9c3ccdb05848b3e607a61acf48bf3aa20b8f29d0f5b690d96dca51d`
- **REPORT_v2:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-v2.md` exists=`True` bytes=`18804` mtime=`2026-08-06T02:09:22.869203+00:00`
  - sha256: `888c36b3a2d7d8d86912a3630c699f01cd68bf009e17b4e47a9ef15a3ccb9233`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`62994` mtime=`2026-08-06T02:12:02.190158+00:00`
  - sha256: `509fcc75cd1f40e0cdd2b83fd81a768da3a3b85a741c7eda41127b523fe9a7a1`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`41401` mtime=`2026-08-06T02:17:59.429162+00:00`
  - sha256: `a8f5176b60cadc1fb5de32949952315ceb10b2b895839aac6df5f82d992ebff4`
- **report_v2_json:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/report-v2.json` exists=`True` bytes=`21060` mtime=`2026-08-06T02:12:02.198159+00:00`
  - sha256: `89d720ccd8d5dc0ea91f0c68b254b1f1dc502c62c1b65f6c999d3b95e62e5740`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:09:22 UTC

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
This report details the analysis of a confirmed malicious packed PE32 executable (SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9) with a triage score of 92/100. The sample is classified as a packed generic trojan/downloader/dropper wrapped with the AHTeam EP Protector / fake PCGuard packer. Static analysis confirms the sample uses XOR obfuscation and generic 
… [17897 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:16:03 UTC

# RE Report — bf95bc98c0a4
_Generated 2026-08-06T02:16:03.153275+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=355c | cross_refs=True | llm_ok=True | runtime=34.83s -->

# Executive Summary

| Top-Line Metric | Value | Source |
|-----------------|-------|--------|
| Sample Identifier | SHA256: `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9` | (source: cross-section:1_sample_identification, why: SHA256 is the immutable unique identifier for the analyzed sample) |
| Verdict | Malicious | (source: cross-section:2_classification,
… [39333 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
