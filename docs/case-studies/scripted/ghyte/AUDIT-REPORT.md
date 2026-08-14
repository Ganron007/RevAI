# Pipeline AUDIT-REPORT — `a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-14T02:25:01.423877+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-14 02:25:01 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567`

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

- source=`llm_judge` verdict=`malicious` confidence=`85`
- key_evidence_count=`6`

```json
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "upatre/zbot",
  "cross_engine_notes": "Local tools (capa, MalCat) indicate behavioral intent through encryption and defense evasion techniques, while VirusTotal confirms high detection rates as a known trojan/downloader. Obfuscation signals are present but are complemented by malicious behavioral evidence.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "encrypt data using RC4 PRGA",
      "why": "Behavioral intent for obfuscation under Defense Evasion (T1027), a common malware technique to hide payloads or communications."
    },
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "hide graphical window",
      "why": "Defense evasion tactic (T1564.003) to conceal malicious activity from users or analysis tools."
    },
    {
      "source": "malcat",
      "query_or_table": "views/anomalies",
      "row_or_rule": "XorInLoop",
      "why": "Code anomaly indicating XOR-based encryption or unpacking operations, often used in malware for obfuscation or payload extraction."
    },
    {
      "source": "malcat",
      "query_or_table": "views/anomalies",
      "row_or_rule": "HugeGapBetweenFunctions",
      "why": "Anomaly suggesting hidden data or code between functions, typical in packed malware to store encrypted payloads."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "Safeguard_103_Simonzh",
      "why": "YARA rule match that may indicate specific malware family or packer signature, contributing to malicious indicators."
    },
    {
      "source": "external_ti",
      "query_or_table": "VirusTotal detection",
      "row_or_rule": "malicious=68",
      "why": "High detection rate by 68/71 engines, with tags like 'spreader' and 'self-delete', confirming known malicious behavior and family association."
    }
  ],
  "summary": "The PE file exhibits multiple behavioral signals including encryption (RC4 PRGA) and window hiding from capa, code anomalies like XOR loops and function gaps from MalCat, and YARA rule matches for potential malware families. VirusTotal corroborates with high detection rates for trojan.upatre/zbot, indicating malicious intent beyond mere obfuscation.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 7 matches",
      "capa: 3 rules"
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
  "ti_enrich": {
    "ok": true,
    "providers": {
      "virustotal": {
        "ok": true,
        "malicious": 68,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 3,
        "reputation": -172,
        "popular_threat_classification": {
          "suggested_threat_label": "trojan.upatre/zbot",
          "popular_threat_name": [
           
… [2602 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`9`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "Packed/protected PE executable using ZProtect/Safeguard protection with RC4 encryption and hidden-window capabilities. The binary is heavily obfuscated with only 6 functions recoverable from a 26KB sample, garbled strings throughout, and many unresolved indirect calls. CAPA confirms RC4 PRGA encryption (T1027), hidden window creation (T1564.003), and command-line argument processing. The combination of commercial-grade packing, cryptographic obfuscation, and stealth window capabilities indicates a malicious payload concealed within the protector wrapper. Persistence mechanisms were not observed in the analysis. C2 network communications were not identified. Defense impairment techniques were not detected.",
  "key_evidence": [
    "YARA: ZProtect_v144_lifeengines and Safeguard_103_Simonzh packer signatures matched",
    "CAPA: 'encrypt data using RC4 PRGA' - RC4 encryption for obfuscation (T1027)",
    "CAPA: 'hide graphical window' - Defense Evasion via Hidden Window (T1564.003)",
    "CAPA: 'accept command line arguments' - Execution via Command and Scripting Interpreter (T1059)",
    "Ghidra: Only 6 functions identified in 26KB binary indicating heavy packing",
    "Ghidra: High cyclomatic complexity in FUN_00401686 (CC=14, 17 blocks) and FUN_00402bdb (CC=15, 35 blocks)",
    "Ghidra: 11 of 12 call targets in FUN_00401686 resolve to sub_0 (unresolved indirect calls typical of packed code)",
    "IDA: 96 strings found but most are garbled random bytes (e.g., '00N,t', 'qH1Hl', 'VXlt|NO') indicating encrypted/compressed data",
    "Ghidra: All 24 imports are GUI-only (USER32, GDI32, KERNEL32) despite hidden-window capability suggesting real payload loaded dynamically"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 35,
  "successful_non_bootstrap_tools": 21,
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
  },
  "depth_coverage": true
}
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-14 02:06:55 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report details the analysis of a Windows PE executable (ghyte.exe) identified as malicious with high confidence (90%). The sample is a heavily packed and obfuscated binary protected by ZProtect/Safeguard commercial-grade protection software. The binary exhibits multiple behavioral indicators of malicious intent, including RC4 encryption for payload obfuscation, hidden window creation for stealth, and command-line argument processing for execution control. VirusTotal corroborates the malicious classification with a 68/71 detection rate, associating the sample with the Upatre/ZBot malware family.\n\nThe analysis reveals a binary that is functionally opaque due to extreme packing, with only 6 recoverable functions from a 26KB sample. The primary observable behavior is the creation of a hidden GUI window and the use of RC4 encryption, which are classic defense evasion techniques. While no direct C2 communications, persistence mechanisms, or data exfiltration were observed in the static analysis, the combination of commercial-grade protection, cryptographic obfuscation, and stealth capabilities strongly indicates a malicious payload concealed within the protector wrapper. The sample's import table is limited to GUI functions, suggesting the real payload is loaded dynamically at runtime.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| SHA256 | a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567 |\n| File Name | ghyte.exe |\n| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |\n| Architecture | x86 (32-bit) |\n| File Size | 26,112 bytes |\n| Entropy | 6.04 bits/byte (whole-file Shannon entropy) |\n| Imphash | a3e8b5e80d5f9f266119a4ac18211954 |\n| Project | malware |\n| Analysis Date | 2026-08-12 |\n\nThe sample is a standard PE32 GUI executable for the x86 architecture. The entropy of 6.04 bits/byte is elevated but not extreme, which is consistent with a packed binary that still contains some structured data and resources. The imphash is a unique identifier for the import table, which in this case is minimal due to the packing. (source: malcat)\n\n## 2. Classification\n\n| Verdict | Confidence | Family | Score |\n|---|---|---|---|\n| **Malicious** | 90% | Upatre/ZBot | 85 |\n\nThe classification is based on a convergence of evidence from multiple tools. The upstream triage verdict is \"malicious\" with a score of 85, and the deep-dive analysis confirms this with 90% confidence. The sample is associated with the Upatre/ZBot malware family based on YARA rule matches and VirusTotal detections. (source: triage verdict.json, deep-dive.json)\n\n**Key Evidence for Malicious Classification:**\n1.  **Behavioral Intent:** CAPA identifies RC4 encryption (T1027) and hidden window creation (T1564.003), which are active defense evasion techniques, not merely protective wrapp
… [21280 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 02:06:55 UTC

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

This report details the analysis of a Windows PE executable (ghyte.exe) identified as malicious with high confidence (90%). The sample is a heavily packed and obfuscated binary protected by ZProtect/Safeguard commercial-grade protection software. The binary exhibits multiple behavioral indicators of malicious intent, including RC4 encryption for payload obfuscation, hidden window creation for stealth, and command-line argument processing for execution control. VirusTotal corroborates the malicious classification with a 68/71 detection rate, associating the sample with the Upatre/ZBot malware family.

The analysis reveals a binary that is functionally opaque due to extreme packing, with only 6 recoverable functions from a 26KB sample. The primary observable behavior is the creation of a hidden GUI window and the use of RC4 encryption, which are classic defense evasion techniques. While no direct C2 communications, persistence mechanisms, or data exfiltration were observed in the static analysis, the combination of commercial-grade protection, cryptographic obfuscation, and stealth capabilities strongly indicates a malicious payload concealed within the protector wrapper. The sample's import table is limited to GUI functions, suggesting the real payload is loaded dynamically at runtime.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| SHA256 | a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567 |
| File Name | ghyte.exe |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Architecture | x86 (32-bit) |
| File Size | 26,112 bytes |
| Entropy | 6.04 bits/byte (whole-file Shannon entropy) |
| Imphash | a3e8b5e80d5f9f266119a4ac18211954 |
| Project | malware |
| Analysis Date | 2026-08-12 |

The sample is a standard PE32 GUI executable for the x86 architecture. The entropy of 6.04 bits/byte is elevated but not extreme, which is consistent with a packed binary that still contains some structured data and resources. The imphash is a unique identifier
… [19335 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 02:20:06 UTC

# RE Report — a59b2cb9f6c7
_Generated 2026-08-14T02:20:06.241513+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=236c | cross_refs=True | llm_ok=True | runtime=67.06s -->

# Executive Summary

The sample with SHA256 hash `a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567` is assessed as **malicious** and likely belongs to the **Upatre/Zbot** malware family, with a high confidence level of 90%. Agreement between the LLM judge and initial v1 analysis supports this verdict, indicating consistent detection across sources.

**Key Findings Table:**

| Aspect | Assessment | Evidence and Interpretation |
|--------|------------|-----------------------------|
| Verdict | Malicious | (source: v1_summary) shows a malicious score of 290, derived from 7 YARA matches and 3 Capa rules, indicating static detection of malicious indicators. (source: deep_dive_agentic) confirms this with 90% confidence from deep analysis. |
| Family | Upatre/Zbot | (source: cross-section:3 Background & Family Lineage) infers family association from Capa rules that identify downloader behaviors and encryption patterns typical of Upatre/Zbot. |
| Confidence | High (90%) | (source: deep_dive_agentic) reflects strong certainty in the verdict, based on comprehensive analysis. |
| Agreement | Consensus | (source: llm_and_v1_agree) demonstrates alignment between the LLM and v1 analysis sources on the malicious classification. |
| Static Analysis | Significant indicators | (source: v1_summary) YARA rules matched 7 times, and Capa identified 3 rules (e.g., encrypt data using RC4 PRGA), suggesting obfuscation and command-line control. |
| Dynamic Analysis | Tools executed, no events recorded | (source: cross-section:5 Behavioral Analysis) Speakeasy and Frida probes were run during sandbox analysis but recorded zero events, possibly due to anti-analysis evasion or lack of environmental triggers. |

**2-Sentence Summary:** This sample is likely a downloader component of the Upatre/Zbot family, commonly used in multi-stage attacks to fetch additional malware such as Zeus banking trojan. Static analysis reveals obfuscation and encryption capabilities, while dynamic analysis in a san
… [41461 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6102` | `3b207028749b1213` |
| `prompt.txt` | `True` | `28096` | `2f6947743086ea46` |
| `pipeline-audit.json` | `True` | `111685` | `4ae0dbb238bdce4c` |
| `AUDIT-REPORT.md` | `True` | `82272` | `804db8be98ba90cd` |
| `REPORT-MASTER-v2.md` | `True` | `21842` | `0ec35ad1448d4d3b` |
| `REPORT-MASTER-v3.md` | `True` | `43976` | `6063e5eec8a380a4` |
| `REPORT-v2.md` | `True` | `21842` | `0ec35ad1448d4d3b` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `44870` | `c3a29a92f77d60ee` |
| `rule.yar` | `True` | `1077` | `68834b1c1677cb0f` |
| `intake-validation.json` | `True` | `2809` | `0d4b245c3e0c273f` |
| `source-decisions.json` | `True` | `1974` | `fa486401504374ae` |
| `malcat-triage.json` | `True` | `16361` | `3eccc6347bdf12f8` |
| `deep_dive/01-tools-raw.json` | `True` | `58037` | `f1a8c9740ec84a23` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3059` | `3274c1beece1a1e9` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `51423` | `9f613e45466399d8` |

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

- **intake_validation:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/intake-validation.json` exists=`True` bytes=`2809` mtime=`2026-08-12T17:23:47.488576+00:00`
  - sha256: `0d4b245c3e0c273fe7d26c78d826a5e3868fadbf8252d2ce578b4607d7976182`
- **malcat_triage:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/malcat-triage.json` exists=`True` bytes=`16361` mtime=`2026-08-13T02:29:17.920837+00:00`
  - sha256: `3eccc6347bdf12f8989aa34c9bf6d74e2f2daf539a2ba76c4b2b9a0293537bfc`
- **source_decisions:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/source-decisions.json` exists=`True` bytes=`1974` mtime=`2026-08-12T17:23:47.488576+00:00`
  - sha256: `fa486401504374ae9435ef5c2600a1f75a4d0fe024abec3309d1c445a4bf1eb2`
- **ghidra_import_log:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/intake-analyzeHeadless.log` exists=`True` bytes=`5949` mtime=`2026-08-12T17:22:43.094539+00:00`
  - sha256: `467178c0f79a9316a067bad6037845a3338f191cad103c46f739303fe0faeae5`
- **ida_bootstrap_log:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/intake-idasql.log` exists=`True` bytes=`212` mtime=`2026-08-12T17:22:44.469542+00:00`
  - sha256: `4d8de8f9fa83ce9cead1b469a5bce4027cd1f2cc60f486a7b3228f36b1e5140f`

#### source_decisions_excerpt

```
{
  "sha256": "a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "All sources (Ghidra, IDA, Malcat) report 24 imports, indicating high consistency. Evidence: {source: tool_summaries, query_or_table: ghidra/ida/malcat, row_or_rule: imports_count, why: Ghidra=24, IDA=24, Malcat=24}"
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA report similar counts (6 vs 7), within 2x, while Malcat reports 8 which may use different criteria. Evidence: {source: tool_summaries, query_or_table: ghidra and ida, row_or_rule: funcs, why: Ghidra=6, IDA=7, Malcat=8}"
  },
  "strings": {
    "source": "ida",
    "confidence": "medium",
    "reason": "IDA reports 96
… [1197 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
    "file_name": "ghyte.exe",
    "file_path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
    "file_size": 26624,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.04,
    "sha256": "a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567",
    "metadata": {},
    "entrypoint_ea": 2688,
    "layout": [
      {
        "name": "header",
        "effective_address
… [15561 more chars]
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
  "rule_count": 3,
  "top_rules": [
    {
      "name": "encrypt data using RC4 PRGA",
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
            "Cryptography",
            "Encrypt Data",
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        },
        {
          "parts": [
            "Cryptography",
            "Generate Pseudo-random Sequence",
            "RC4 PRGA"
          ],
          "objective": "Cryptography",
          "behavior": "Generate Pseudo-random Sequence",
          "method": "RC4 PRGA",
          "id": "C0021.004"
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
      "name": "hide graphical window",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Hide Artifacts",
            "Hidden Window"
          ],
          "tactic": "Defense Evasion",
          "technique": "Hide Artifacts",
          "subtechnique": "Hidden Window",
          "id": "T1564.003"
        }
      ],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 26624,
  "duration_s": 2.09,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 12748,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
      "rule": "Safeguard_103_Simonzh",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2688,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "ZProtect_v144_lifeengines",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2688,
          "length": 23,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Spywaller.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` 
… [1147 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 72,
  "strings_sampled": 70,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "7Richu",
    "`.data",
    "VXlt|NO",
    "%h@~qU",
    "}|)8Or6",
    "`X+ww76m@@",
    "auf je",
    "%h@pfQ",
    "H]wyvK`",
    "y8u(@%",
    "mf tTl",
    "%%:}[t",
    "|`|s\\$:~",
    "KQjO:N",
    "%@%?vp",
    "t7{p|Xz",
    "2uPj1hp@@",
    "GGGGBBBBIu",
    "SwW&:~8Ol",
    "8n+|Bj",
    "terras",
    "summer",
    "momenr",
    "dip quip",
    "static",
    "DestroyWindow",
    "button",
    "SetTimer",
    "KillTimer",
    "SetWindowPos",
    "GetWindowRect",
    "FillRect",
    "LoadCursorA",
    "LoadIconA",
    "SendMessageA",
    "DefWindowProcA",
    "RegisterClassExA",
    "CreateWindowExA",
    "LoadBitmapA",
    "TranslateMessage",
    "BeginPaint",
    "DispatchMessageA",
    "EndPaint",
    "GetMessageA",
    "PostQuitMessage",
    "ShowWindow",
    "UpdateWindow",
    "user32.dll",
    "GetCommandLineA",
    "GetModuleHandleA",
    "GetLastError",
    "kernel32.dll",
    "TextOutA",
    "gdi32.dll",
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">",
    "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">",
    "<security>",
    "<requestedPrivileges>",
    "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>",
    "</requestedPrivileges>",
    "</security>",
    "</trustInfo>",
    "</assembly>",
    "\"\"\"\"\"\"\"",
    "\"\"\"#\"\"\"",
    "\"\"\"DB\"\"",
    "\"\"\"BB\"\"",
    "\"\"$BD\"\"",
    "\"\"$\"$\"\""
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 72
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 5.65,
  "size_bytes": 26624,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
    "file_name": "ghyte.exe",
    "file_path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
    "file_size": 26624,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.04,
    "sha256": "a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567",
    "metadata": {},
    "entrypoint_ea": 2688,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 39
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 10752,
        "virtual_size": 12288,
        "rights": "RX",
        "entropy": 137
      },
      {
        "name": ".data",
        "effective_address": 13312,
        "physical_size": 3584,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 72
      },
      {
        "name": ".rsrc",
        "effective_address": 17408,
        "physical_size": 11264,
        "virtual_size": 12288,
        "rights": "R",
        "entropy": 52
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 91,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "HugeGapBetweenFunctions",
        "desc": "There is a huge gap between two functions with medium-to-high entropy, often means that data is stored there",
        "category": "code",
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
        "name": "NoValidCertificate",
        "desc": "Certificate data directory does not point to a valid certificate (maybe corrupted ?)",
        "category": "integrity",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "XorInLoop",
        "desc": "XOR instruction in a loop",
        "category": "code",
        "level": 3,
        "num_hits": 1
      }
    ],
    "anomaly_locations": {
      "NoChecksum": [
        {
          "ea": 328,
          "context": ""
        }
      ],
      "XorInLoop": [
        {
          "ea": 8221,
          "context": ""
        }
      ]
    },
    "yara_hits": [
      {
        "id": "MSVC_2005_linker",
        "category": "compiler",
        "reliability": 60,
        "type": "INFO",
        "description": "detects used visual studio version based on linker information",
        "num_patterns": 0
      },
      {
        "id": "MSVC_2008_rich",
        "category": "compiler",
        "reliability": 80,
        "type": "INFO",
        "description": "detects used visual studio version based on rich header information",
        "num_patterns": 0
      }
    ],
    "strings": [
      {
        "ea": 17712,
        "summary": "<assembly xmlns=..fo>\r\n</assembly>"
      },
      {
        "ea": 14284,
        "summary": "DestroyWindow"
      },
      {
        "ea": 14259,
        "summary": "dip quip"
      },
      {
        "ea": 16742,
        "sum
… [30764 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "encrypt data using RC4 PRGA capa top_rules Behavioral intent for obfuscation under Defense Evasion (T1027), a common mal",
    "hide graphical window capa top_rules Defense evasion tactic (T1564.003) to conceal malicious activity from users or anal",
    "XorInLoop views/anomalies Code anomaly indicating XOR-based encryption or unpacking operations, often used in malware fo",
    "HugeGapBetweenFunctions views/anomalies Anomaly suggesting hidden data or code between functions, typical in packed malw",
    "Safeguard_103_Simonzh yara matches YARA rule match that may indicate specific malware family or packer signature, contri"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "upatre/zbot",
  "score": 85,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "encrypt data using RC4 PRGA",
      "why": "Behavioral intent for obfuscation under Defense Evasion (T1027), a common malware technique to hide payloads or communications."
    },
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "hide graphical window",
      "why": "Defense evasion tactic (T1564.003) to conceal malicious activity from users or analysis tools."
    },
    {
      "source": "malcat",
      "query_or_table": "views/anomalies",
      "row_or_rule": "XorInLoop",
      "why": "Code anomaly indicating XOR-based encryption or unpacking operations, often used in malware for obfuscation or payload extraction."
    },
    {
      "source": "malcat",
      "query_or_table": "views/anomalies",
      "row_or_rule": "HugeGapBetweenFunctions",
      "why": "Anomaly suggesting hidden data or code between functions, typical in packed malware to store encrypted payloads."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "Safeguard_103_Simonzh",
      "why": "YARA rule match that may indicate specific malware family or packer signature, contributing to malicious indicators."
    },
    {
      "source": "external_ti",
      "query_or_table": "VirusTotal detection",
      "row_or_rule": "malicious=68",
      "why": "High detection rate by 68/71 engines, with tags like 'spreader' and 'self-delete', confirming known malicious behavior and family association."
    }
  ],
  "summary": "The PE file exhibits multiple behavioral signals including encryption (RC4 PRGA) and window hiding from capa, code anomalies like XOR loops and function gaps from MalCat, and YARA rule matches for potential malware families. VirusTotal corroborates with high detection rates for trojan.upatre/zbot, indicating malicious intent beyond mere obfuscation."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/prompt.txt` exists=`True` bytes=`28096` mtime=`2026-08-14T02:02:46.931360+00:00`
  - sha256: `2f6947743086ea4607822b72071756ad6afc08f2bcfdd72bf92f246172f4fb46`
- **verdict:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/verdict.json` exists=`True` bytes=`6102` mtime=`2026-08-14T02:03:53.675111+00:00`
  - sha256: `3b207028749b12135e0c37d0045dc66c5c086d1ab5b682104fee94edffe4a729`

#### prompt_excerpt

```
# Triage evidence
sha256: a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567
sample_path: /opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe
ghidra_session: ghidra-pe-a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567
ida_session: ida-a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — All sources (Ghidra, IDA, Malcat) report 24 imports, indicating high consistency. Evidence: {source: tool_summaries, query_or_table: ghidra/ida/malcat, row_or_rule: imports_count, why: Ghidra=24, IDA=24, Malcat=24}
- functions: ghidra (confidence=medium) — Ghidra and IDA report similar counts (6 vs 7), within 2x, while Malcat reports 8 which may use different criteria. Evidence: {source: tool_summaries, query_or_table: ghidra and ida, row_or_rule: funcs, why: Ghidra=6, IDA=7, Malcat=8}
- strings: ida (confidence=medium) — IDA repo
… [27052 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "upatre/zbot",
  "cross_engine_notes": "Local tools (capa, MalCat) indicate behavioral intent through encryption and defense evasion techniques, while VirusTotal confirms high detection rates as a known trojan/downloader. Obfuscation signals are present but are complemented by malicious behavioral evidence.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "encrypt data using RC4 PRGA",
      "why": "Behavioral intent for obfuscation under Defense Evasion (T1027), a common malware technique to hide payloads or communications."
    },
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "hide graphical window",
      "why": "Defense evasion tactic (T1564.003) to conceal malicious activity from users or analysis tools."
    },
    {
      "source": "malcat",
      "query_or_table": "views/anomalies",
      "row_or_rule": "Xo
… [5102 more chars]
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
  "rule_count": 3,
  "top_rules": [
    {
      "name": "encrypt data using RC4 PRGA",
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
            "Cryptography",
            "Encrypt Data",
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        },
        {
          "parts": [
            "Cryptography",
            "Generate Pseudo-random Sequence",
            "RC4 PRGA"
          ],
          "objective": "Cryptography",
          "behavior": "Generate Pseudo-random Sequence",
          "method": "RC4 PRGA",
          "id": "C0021.004"
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
      "name": "hide graphical window",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Hide Artifacts",
            "Hidden Window"
          ],
          "tactic": "Defense Evasion",
          "technique": "Hide Artifacts",
          "subtechnique": "Hidden Window",
          "id": "T1564.003"
        }
      ],
      "mbc": []
    }
  ],
  "timeout_s": 60,
  "sample_size": 26624,
  "duration_s": 1.02,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 26624,
  "duration_s": 0.03,
  "import_count": 24,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 12748,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
      "rule": "Safeguard_103_Simonzh",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2688,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "ZProtect_v144_lifeengines",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2688,
          "length": 23,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Spywaller.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` 
… [1125 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 72,
  "strings_sampled": 70,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "7Richu",
    "`.data",
    "VXlt|NO",
    "%h@~qU",
    "}|)8Or6",
    "`X+ww76m@@",
    "auf je",
    "%h@pfQ",
    "H]wyvK`",
    "y8u(@%",
    "mf tTl",
    "%%:}[t",
    "|`|s\\$:~",
    "KQjO:N",
    "%@%?vp",
    "t7{p|Xz",
    "2uPj1hp@@",
    "GGGGBBBBIu",
    "SwW&:~8Ol",
    "8n+|Bj",
    "terras",
    "summer",
    "momenr",
    "dip quip",
    "static",
    "DestroyWindow",
    "button",
    "SetTimer",
    "KillTimer",
    "SetWindowPos",
    "GetWindowRect",
    "FillRect",
    "LoadCursorA",
    "LoadIconA",
    "SendMessageA",
    "DefWindowProcA",
    "RegisterClassExA",
    "CreateWindowExA",
    "LoadBitmapA",
    "TranslateMessage",
    "BeginPaint",
    "DispatchMessageA",
    "EndPaint",
    "GetMessageA",
    "PostQuitMessage",
    "ShowWindow",
    "UpdateWindow",
    "user32.dll",
    "GetCommandLineA",
    "GetModuleHandleA",
    "GetLastError",
    "kernel32.dll",
    "TextOutA",
    "gdi32.dll",
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">",
    "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">",
    "<security>",
    "<requestedPrivileges>",
    "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>",
    "</requestedPrivileges>",
    "</security>",
    "</trustInfo>",
    "</assembly>",
    "\"\"\"\"\"\"\"",
    "\"\"\"#\"\"\"",
    "\"\"\"DB\"\"",
    "\"\"\"BB\"\"",
    "\"\"$BD\"\"",
    "\"\"$\"$\"\""
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 72
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.3,
  "size_bytes": 26624,
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
  "sample": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
  "disassembly": {
    "0x00401680": "\u250c 6: entry0 ();\n\u2502           0x00401680      e801000000     call fcn.00401686\n\u2514           0x00401685      c3             ret",
    "0x00401686": "; CALL XREF from entry0 @ 0x401680(x)\n\u250c 299: fcn.00401686 ();\n\u2502           0x00401686      55             push ebp\n\u2502           0x00401687      8bec           mov ebp, esp\n\u2502           0x00401689      ff150c404000   call dword [sym.imp.kernel32.dll_GetCommandLineA] ; 0x40400c ; \"0M\" ; LPSTR GetCommandLineA(void)\n\u2502           0x0040168f      a374444000     mov dword [0x404474], eax   ; [0x404474:4]=0\n\u2502           0x00401694      6a00           push 0\n\u2502           0x00401696      ff1508404000   call dword [sym.imp.kernel32.dll_GetModuleHandleA] ; 0x404008 ; \"BM\" ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)\n\u2502           0x0040169c      892dcf414000   mov dword [0x4041cf], ebp   ; [0x4041cf:4]=97 ; \"a\"\n\u2502           0x004016a2      a304444000     mov dword [0x404404], eax   ; [0x404404:4]=0\n\u2502           0x004016a7      a3c7414000     mov dword [0x4041c7], eax   ; [0x4041c7:4]=17\n\u2502           0x004016ac      c705f04340..   mov dword [0x4043f0], 0x30  ; '0'\n\u2502                                                                      ; [0x4043f0:4]=0\n\u2502           0x004016b6      c705f44340..   mov dword [0x4043f4], 2     ; [0x4043f4:4]=0\n\u2502       \u250c\u2500< 0x004016c0      eb04           jmp 0x4016c6\n..\n\u2502       \u2502   ; CODE XREF from fcn.00401686 @ 0x4016c0(x)\n\u2502       \u2514\u2500> 0x004016c6      c705f84340..   mov dword [0x4043f8], 0x403051 ; 'Q0@'\n\u2502                                                                      ; [0x4043f8:4]=0\n\u2502           0x004016d0      c705fc4340..   mov dword [0x4043fc], 0     ; [0x4043fc:4]=0\n\u2502           0x004016da      c705004440..   mov dword [0x404400], 0     ; [0x404400:4]=0\n\u2502           0x004016e4      68007f0000     push 0x7f00\n\u2502           0x004016e9      6a00           push 0\n\u2502           0x004016eb      ff1534404000   call dword [sym.imp.user32.dll_LoadCursorA] ; 0x404034 ; \"4L\" ; HCURSOR LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName)\n\u2502           0x004016f1      a30c444000     mov dword [0x40440c], eax   ; [0x40440c:4]=0\n\u2502           0x004016f6      68007f0000     push 0x7f00\n\u2502           0x004016fb      6a00           push 0\n\u2502           0x004016fd      ff1518404000   call dword [sym.imp.user32.dll_LoadIconA] ; 0x404018 ; \"BL\" ; HICON LoadIconA(HINSTANCE hInstance, LPCSTR lpIconName)\n\u2502           0x00401703      a308444000     mov dword [0x404408], eax   ; [0x404408:4]=0\n\u2502           0x00401708      a31c444000     mov dword [0x40441c], eax   ; [0x40441c:4]=0\n\u2502           0x0040170d      c705184440..   mov dword [0x404418], 0x40439a ; [0x404418:4]=0\n\u2502           0x00401717      c705104440..   mov dword [0x404410], 0xf   ; [0x404410:4]=0\n\u2502           0x00401721      68f0434000     push 0x4043f0\n\u2502           0x00401726      ff1524404000   call dword [sym.imp.user32.dll_RegisterClassExA] ; 0x404024 ; \"pL\" ; ATOM RegisterClassExA(const WNDCLASSEXA *ARG_0)\n\u2502           0x0040172c      6a00           push 0\n\u2502           0x0040172e      ff35c7414000   push dword [0x4041c7]\n\u2502    
… [213 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
    "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
    "exists": true,
    "hook_candidates": [
      "user32.dll!LoadIconA",
      "user32.dll!SendMessageA",
      "user32.dll!DefWindowProcA",
      "user32.dll!RegisterClassExA",
      "user32.dll!CreateWindowExA",
      "kernel32.dll!GetModuleHandleA",
      "kernel32.dll!GetCommandLineA",
      "kernel32.dll!GetLastError",
      "gdi32.dll!TextOutA"
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
  "checked": 9,
  "hits": 8,
  "misses": [
    "Ghidra: High cyclomatic complexity in FUN_00401686 (CC=14, 17 blocks) and FUN_00402bdb (CC=15, 35 blocks)"
  ],
  "hit_examples": [
    "YARA: ZProtect_v144_lifeengines and Safeguard_103_Simonzh packer signatures matched",
    "CAPA: 'encrypt data using RC4 PRGA' - RC4 encryption for obfuscation (T1027)",
    "CAPA: 'hide graphical window' - Defense Evasion via Hidden Window (T1564.003)",
    "CAPA: 'accept command line arguments' - Execution via Command and Scripting Interpreter (T1059)",
    "Ghidra: Only 6 functions identified in 26KB binary indicating heavy packing"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Packed/protected PE executable using ZProtect/Safeguard protection with RC4 encryption and hidden-window capabilities. The binary is heavily obfuscated with only 6 functions recoverable from a 26KB sample, garbled strings throughout, and many unresolved indirect calls. CAPA confirms RC4 PRGA encrypt",
  "key_evidence": [
    "YARA: ZProtect_v144_lifeengines and Safeguard_103_Simonzh packer signatures matched",
    "CAPA: 'encrypt data using RC4 PRGA' - RC4 encryption for obfuscation (T1027)",
    "CAPA: 'hide graphical window' - Defense Evasion via Hidden Window (T1564.003)",
    "CAPA: 'accept command line arguments' - Execution via Command and Scripting Interpreter (T1059)",
    "Ghidra: Only 6 functions identified in 26KB binary indicating heavy packing",
    "Ghidra: High cyclomatic complexity in FUN_00401686 (CC=14, 17 blocks) and FUN_00402bdb (CC=15, 35 blocks)",
    "Ghidra: 11 of 12 call targets in FUN_00401686 resolve to sub_0 (unresolved indirect calls typical of packed code)",
    "IDA: 96 strings found but most are garbled random bytes (e.g., '00N,t', 'qH1Hl', 'VXlt|NO') indicating encrypted/compressed data",
    "Ghidra: All 24 imports are GUI-only (USER32, GDI32, KERNEL32) despite hidden-window capability suggesting real payload loaded dynamically"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
… [4225 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
    "file_name": "ghyte.exe",
    "file_path": "/
… [33708 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 3,
  "top_rules": [
    {
      "name": "encrypt data using RC4 PRGA",
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
  
… [1784 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 26624,
  "duration_s": 0.03,
  "import_count": 24,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 72,
  "strings_sampled": 70,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "7Richu",
    "`.data",
    "VXlt|NO",
    "%h@~qU",
    "}|)8Or6",
    "`X+ww76m@@",
    "auf je",
    "%h@pfQ",
    "H]wyvK`",
    "y8u(@%",
    "mf tTl",
    "%%:}[t",
    "|`|s\\$:~",
    "KQjO:N",
    "%@%?vp",
    "t7{p|Xz",
    "2uPj1hp@@",
    "GGGGBBBBIu"
… [1554 more chars]
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
  "sample": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
  "disassembly": {
    "0x00401680": "\u250c 6: entry0 ();\n\u2502           0x00401680      e801000000     call fcn.00401686\n\u2514           0x00401685      c3             ret",
    "0x00401686": "; CALL XREF from entry0 @ 0x401680(x)\n\u250c 299: fcn.00401686
… [3313 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_r
… [15 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
    "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
    "exists": true,
    "hook_candidates": [
      "user32.dll!LoadIconA",
      "user32.dll!SendMessageA",
      "user32.dll!DefWindowProcA",
      "user32.dll!RegisterClassExA",
      "user32.dll!CreateWin
… [159 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 10752,
      "entropy": 6.6346,
      "executable": true,
      "writable": false
    },
    {
      "name": ".data",
      "size": 3584,
      "entropy": 3.3611,
      "executable": fals
… [249 more chars]
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
… [1768 more chars]
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
    "elapsed_s": 0.26,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.12,
 
… [101 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "suspicious",
  "name": null,
  "score": 4
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
      "name": "FUN_00402bdb",
      "address": "4205531",
      "size": "337"
    },
    {
      "name": "FUN_00401686",
      "address": "4200070",
      "size": "299"
    },
    {
      "name": "FUN_004017bb",
      "address": "4200379",
      "size": "218"
    },
    {
      "name": "FUN_00402ebf",
      "address": "4
… [511 more chars]
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
      "name": "TextOutA",
      "module": "GDI32.DLL"
    },
    {
      "name": "GetCommandLineA",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetLastError",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetModuleHandleA",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "BeginPaint",
      "modu
… [1697 more chars]
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
      "content": "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\r\n    <security>\r\n      <requestedPrivileges>\r\n        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>\r\n      <
… [3180 more chars]
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
      "address": "4200064",
      "size": "6"
    },
    {
      "name": "FUN_00401686",
      "address": "4200070",
      "size": "299"
    },
    {
      "name": "FUN_004017bb",
      "address": "4200379",
      "size": "218"
    },
    {
      "name": "FUN_00402a06",
      "address": "4205062",

… [511 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567.json"
}
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
      "content": "00N,t",
      "address": "4198485"
    },
    {
      "content": "qH1Hl",
      "address": "4198533"
    },
    {
      "content": "VXlt|NO",
      "address": "4198691"
    },
    {
      "content": "$Ja6U\u000b",
      "address": "4198748"
    },
    {
      "content": "Il8NL ",
      "address": "4198782"
    }
… [1983 more chars]
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
      "content": "HOd:#",
      "address": "4211267"
    },
    {
      "content": "user32.dll",
      "address": "4214052"
    },
    {
      "content": "kernel32.dll",
      "address": "4214118"
    },
    {
      "content": "gdi32.dll",
      "address": "4214144"
    }
  ],
  "row_count": 4,
  "total_row_count": 4,
  "truncate
… [238 more chars]
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
      "content": "RegisterClassExA",
      "address": "4213874"
    },
    {
      "content": "user32.dll",
      "address": "4214052"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567",
  "audit
… [106 more chars]
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
      "func_name": "",
      "func_addr": "",
      "string_value": "summer",
      "string_addr": "4211615"
    },
    {
      "func_name": "",
      "func_addr": "",
      "string_value": "summer",
      "string_addr": "4211615"
    },
    {
      "func_name": "",
      "func_addr": ""
… [1241 more chars]
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
  "rows": [
    {
      "func_name": "entry",
      "func_addr": "4200064",
      "size": "6",
      "instruction_count": "1",
      "block_count": "2",
      "cyclomatic_complexity": "2",
    
… [1804 more chars]
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
      "content": "terras",
      "address": "4211603",
      "length": "7"
    },
    {
      "content": "summer",
      "address": "4211615",
      "length": "7"
    },
    {
      "content": "Arial",
      "address": "4211629",
      "length": "6"
    },
    {
      "content": "dip quip",
      "address": "4211635
… [1053 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "name",
    "data_type",
    "size",
    "value_repr",
    "segment_name",
    "is_string",
    "is_initialized"
  ],
  "rows": [
    {
      "address": "4194304",
      "name": "IMAGE_DOS_HEADER_00400000",
      "data_type": "IMAGE_DOS_HEADER",
      "size": "128",
      "value_repr": "",
      "segment_name": "",
      "is_string": "0",
      "is_initialized":
… [6953 more chars]
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
… [866 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_name"
}
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
      "src_func_addr": "4200064",
      "src_func_name": "entry",
      "dst_func_addr": "4200070",
      "dst_func_name": "FUN_00401686",
      "call_site": "4200064"
    },
    {
      "src_func_addr": "4200070",
      "src_func_name": "FUN_00401686",
      
… [8257 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567",
  "audit_path": "/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/audit.jsonl"
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 3,
  "top_rules": [
    {
      "name": "encrypt data using RC4 PRGA",
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
  
… [1784 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

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
  "source": "ida_query",
  "session_id": "ida-a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567",
  "audit_path": "/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "operands",
    "size"
  ],
  "rows": [
    {
      "address": "4205531",
      "mnemonic": "LEA",
      "operands": "EDX, [0x4044c8]",
      "size": "6"
    },
    {
      "address": "4205537",
      "mnemonic": "MOV",
      "operands": "ECX, EDX",
      "size": "2"
    },
    {
      "address": "4205539",
      "mnemonic": "MOV",
      "operand
… [4592 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567",
  "audit_path": "/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "operands",
    "size"
  ],
  "rows": [
    {
      "address": "4205801",
      "mnemonic": "INC",
      "operands": "AL",
      "size": "2"
    },
    {
      "address": "4205803",
      "mnemonic": "CMP",
      "operands": "AL, 0x0",
      "size": "2"
    },
    {
      "address": "4205805",
      "mnemonic": "JNZ",
      "operands": "0x00402cf
… [3298 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/deep_dive/01-tools-raw.json` exists=`True` bytes=`58037` mtime=`2026-08-13T02:29:17.923837+00:00`
  - sha256: `f1a8c9740ec84a2378ec56e5615e2a9e5b670f58f073387cdbf3979033056ea3`
- **sql_evidence:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/deep_dive/05-deep-dive.json` exists=`True` bytes=`3059` mtime=`2026-08-12T17:27:02.284429+00:00`
  - sha256: `3274c1beece1a1e95da00a77f88721c74d3fa4dc6510244a37e65ebeab191337`

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
  "summary": "Packed/protected PE executable using ZProtect/Safeguard protection with RC4 encryption and hidden-window capabilities. The binary is heavily obfuscated with only 6 functions recoverable from a 26KB sample, garbled strings throughout, and many unresolved indirect calls. CAPA confirms RC4 PRGA encryption (T1027), hidden window creation (T1564.003), and command-line argument processing. The combination of commercial-grade packing, cryptographic obfuscation, and stealth window capabilities indicates a malicious payload concealed within the protector wrapper. Persistence mechanisms were not observed in the analysis. C2 network communications were not identified. Defense impair
… [2259 more chars]
```

- **agentic:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`266317` mtime=`2026-08-12T17:27:02.283428+00:00`
  - sha256: `e08d78acf39a4ab42f898bc2bd95d74d4d9bec597204a531c2f77ed8753dcdf5`

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

- **rule_yar:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/rule.yar` exists=`True` bytes=`1077` mtime=`2026-08-12T17:27:05.185435+00:00`
  - sha256: `68834b1c1677cb0f44fef1cdcff576314d1eeaf50f5c1cce4870d0344a7153b1`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T17:27:05.186553+00:00
import "pe"
rule CADRE_v2_upatre_a59b2cb9f6c7 {
    meta:
        description = "RevAI v2 auto rule for upatre"
        sha256 = "a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567"
        family = "upatre"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "`X+ww76m@@" ascii wide
        $s2 = "|`|s\\$:~" ascii wide
        $s3 = "2uPj1hp@@" ascii wide
        $s4 = "GGGGBBBBIu" ascii wide
        $s5 = "SwW&:~8Ol" ascii wide
        $s6 = "dip quip" ascii wide
        $s7 = "DestroyWindow" ascii wide
        $s8 = "SetTimer" ascii wide
… [275 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/REPORT-MASTER-v2.md` exists=`True` bytes=`21842` mtime=`2026-08-14T02:06:55.712259+00:00`
  - sha256: `0ec35ad1448d4d3bfca0de7c8a7f74df3c3fc5f086d6228b63584e0a414ed447`
- **REPORT_MASTER_v3:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/REPORT-MASTER-v3.md` exists=`True` bytes=`43976` mtime=`2026-08-14T02:20:06.246336+00:00`
  - sha256: `6063e5eec8a380a4991463a794766f241751cfbd65deb1843c56514c35ae2b9b`
- **REPORT_v2:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/REPORT-v2.md` exists=`True` bytes=`21842` mtime=`2026-08-14T02:06:55.711259+00:00`
  - sha256: `0ec35ad1448d4d3bfca0de7c8a7f74df3c3fc5f086d6228b63584e0a414ed447`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`62128` mtime=`2026-08-14T02:11:16.606535+00:00`
  - sha256: `0d1f75e6ebbd3e8c02be042d74ade7cc688523c469b14880af60b09dd76b51aa`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`44870` mtime=`2026-08-14T02:25:01.375154+00:00`
  - sha256: `c3a29a92f77d60ee75dbb91777ce4e3277b3a80d65e004ae4c70a53ec54bef99`
- **report_v2_json:** `/opt/samples/logs/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/report-v2.json` exists=`True` bytes=`24780` mtime=`2026-08-14T02:11:16.611535+00:00`
  - sha256: `4310e9425a791cd2a015cd8d3a4788d1974bfbf96d035746faa8fc3e8294cd01`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 02:06:55 UTC

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

This report details the analysis of a Windows PE executable (ghyte.exe) identified as malicious with high confidence (90%). The sample is a heavily packed and obfuscated binary protected by ZProtect/Safeguard commercial-grade protection software. The binary exhibits multiple behavioral indicators of malicious intent, including RC4 encryption for payload obfuscation, hidden window creation for stealth, and command-li
… [20935 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 02:20:06 UTC

# RE Report — a59b2cb9f6c7
_Generated 2026-08-14T02:20:06.241513+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=236c | cross_refs=True | llm_ok=True | runtime=67.06s -->

# Executive Summary

The sample with SHA256 hash `a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567` is assessed as **malicious** and likely belongs to the **Upatre/Zbot** malware family, with a high confidence level of 90%. Agreement between the LLM judge and initial v1 analysis supports this verdict, indicating consistent detection across sources.

**Key Findings Table:**

| Aspect | Assessmen
… [43061 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
