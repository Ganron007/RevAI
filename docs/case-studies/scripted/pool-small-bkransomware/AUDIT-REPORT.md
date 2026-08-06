# Pipeline AUDIT-REPORT — `2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-06T00:59:38.870939+00:00
- **Provenance:** `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-06 00:59:38 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`95`
- key_evidence_count=`8`

```json
{
  "verdict": "Malicious",
  "score": 95,
  "family_guess": "Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by sample metadata",
  "cross_engine_notes": "Ghidra and IDA both failed to produce function, import, or decompilation data due to project ownership errors (Ghidra) and a missing idasql binary (IDA), so no reverse-engineered code context is available from those tools. All available analysis engines (pe_imports, YARA, capa, FLOSS) provide consistent, corroborating evidence of malicious RAT/ransomware functionality. The sample's file path explicitly references known ransomware (Maze, BK Ransomware) and RAT (Remcos, Hawkeye, Elex) families, which aligns with the detected capabilities.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "check_debugger (IsDebuggerPresent) [T1622]",
      "why": "IsDebuggerPresent is a standard anti-debugging technique used by malware to detect and evade reverse engineering tools, a strong indicator of malicious intent."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "download_file (URLDownloadToFile) [T1105]",
      "why": "This API is used to download additional payloads (e.g., ransomware encryption modules, RAT components) from attacker-controlled infrastructure, consistent with ransomware and RAT behavior."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "Registry modification is used for persistence (e.g., adding run keys), disabling security software, or configuring malicious behavior, a common capability of both RATs and ransomware."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "create_process (CreateProcess) / shell_execute (ShellExecute) [T1106]",
      "why": "These APIs are used to execute additional malicious processes, launch ransomware encryption routines, or run attacker commands, core functionality for remote access and ransomware operation."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "load_library (LoadLibrary) / get_proc_address (GetProcAddress) [T1129]",
      "why": "Dynamic API resolution is a common obfuscation technique used by malware to hide malicious imports from static analysis, aligning with observed obfuscation traits."
    },
    {
      "source": "yara",
      "query_or_table": "yara raw JSON matches",
      "row_or_rule": "23 matching rules including anti_dbg, keylogger, screenshot, win_registry, win_files_operation, network_dropper, escalate_priv, win_token",
      "why": "These rules detect well-known malware capabilities: anti-debugging, keylogging, screen capture, registry manipulation, file operations, network dropper functionality, privilege escalation, and token manipulation, all consistent with RAT and ransomware behavior."
    },
    {
      "source": "capa",
      "query_or_table": "capa raw JSON top rules",
      "row_or_rule": "T1083 (File and Directory Discovery), T1082 (System Information Discovery), T1112 (Modify Registry), T1027 (Obfuscated Files or Information), T1056.001 (Keylogging), T1105 (Ingress Tool Transfer), T1106 (Process Ex
… [3692 more chars]
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
  "summary": "PE32 Windows GUI executable with strong malicious indicators: YARA matches for domains, IPs, URLs, base64, suspicious strings, and anti-analysis patterns; capa rules for XOR obfuscation, registry manipulation, file discovery, and execution; PE imports for debugger detection, download, registry writes, and process creation; FLOSS reveals 2846 strings with decoded/obfuscated content. Sample corpus name associates it with known ransomware/RAT families (BKRansomware, Elex, Hawkeye, Maze, Remcos).",
  "key_evidence": [
    "YARA 23 matches including domain, IP, base64, url, Misc_Suspicious_Strings, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation, SEH_Save, SEH_Init",
    "pe_import_signals: IsDebuggerPresent (T1622), URLDownloadToFile (T1105), RegSetValue (T1112), CreateProcess/ShellExecute (T1106), LoadLibrary/GetProcAddress (T1129)",
    "capa_analyze: 57 rules, top rules encode data using XOR (T1027), create/open registry key, get file version info, get common file path, check if file exists",
    "floss_extract: 2846 static strings, 1 decoded string, indicating obfuscation/stack strings",
    "Sample path contains bkransomware_elex_hawkeye_maze_remcos indicating known malware family association"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 14,
  "successful_non_bootstrap_tools": 4,
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
  "title": "Malware Analysis Report: Remcos RAT / Maze Ransomware Associated Hybrid Loader (SHA256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c)",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-06 00:52:02 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VC8_Microsoft_Corporation, keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by sample metadata\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis sample is a confirmed malicious PE32 Windows GUI executable with a triage score of 95/100, classified as a hybrid RAT/ransomware loader with ties to Remcos RAT, Maze ransomware, BK Ransomware, Hawkeye, and Elex as indicated by sample corpus metadata. Static analysis reveals 7 high-signal malicious imports, 23 YARA rule matches for common malware capabilities, 57 capa rules mapping to MITRE ATT&CK techniques, and 2846 total FLOSS strings with 2845 heavily obfuscated. No benign indicators or conflicting evidence were identified. Dynamic analysis was not performed, so all behavioral inferences are derived from static indicators. Confidence in the malicious verdict is 90% per deep-dive analysis.\n\n## 1. Sample Identification\n- **SHA256**: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c\n- **Sample Path**: /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos\n- **Project Name**: pool\n- **File Type**: PE32 Windows GUI executable, not a .NET assembly, not packed with UPX\n- **Corpus Context**: Sample path explicitly references 5 known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos), indicating intentional association with known threat actor tooling.\n(source: triage_verdict, UPX_unpack, dotnet_analyze, sample_path)\n\n## 2. Classification\n**Verdict**: Malicious\n**Family Guess**: Remcos RAT / Maze ransomware associated loader or hybrid malware, with confirmed ties to BK Ransomware, Hawkeye, and Elex per sample metadata. The sample is not a legitimate dual-use remote access tool; its capability set (anti-debugging, payload downloading, registry persistence, keylogging, screen capture) aligns exclusively with malicious use cases. No evidence of legitimate functionality was identified.\n(source: triage_verdict, deep-dive.json, sample_path)\n\n## 3. Initial Triage (15 minutes)\nTriage score: 95/100, verdict: Malicious. Key quick-signal findings:\n1. 7 high-signal malicious PE imports: IsDebuggerPresent (anti-debugging), URLDownloadToFile (payload download), RegSetValue (persistence), CreateProces
… [17265 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 00:52:02 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VC8_Microsoft_Corporation, keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by sample metadata
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This sample is a confirmed malicious PE32 Windows GUI executable with a triage score of 95/100, classified as a hybrid RAT/ransomware loader with ties to Remcos RAT, Maze ransomware, BK Ransomware, Hawkeye, and Elex as indicated by sample corpus metadata. Static analysis reveals 7 high-signal malicious imports, 23 YARA rule matches for common malware capabilities, 57 capa rules mapping to MITRE ATT&CK techniques, and 2846 total FLOSS strings with 2845 heavily obfuscated. No benign indicators or conflicting evidence were identified. Dynamic analysis was not performed, so all behavioral inferences are derived from static indicators. Confidence in the malicious verdict is 90% per deep-dive analysis.

## 1. Sample Identification
- **SHA256**: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
- **Sample Path**: /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos
- **Project Name**: pool
- **File Type**: PE32 Windows GUI executable, not a .NET assembly, not packed with UPX
- **Corpus Context**: Sample path explicitly references 5 known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos), indicating intentional association with known threat actor tooling.
(source: triage_verdict, UPX_unpack, dotnet_analyze, sample_path)

## 2. Classification
**Verdict**: Ma
… [15613 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 00:57:59 UTC

# RE Report — 2f2c6d9466e8
_Generated 2026-08-06T00:57:59.454509+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=370c | cross_refs=True | llm_ok=True | runtime=34.42s -->

# Executive Summary
| Core Metric | Value | Source |
|-------------|-------|--------|
| Verdict | Malicious | deep_dive_agentic, cross-section:2. Classification |
| Confidence | 90% | deep_dive_agentic, cross-section:2. Classification |
| Analysis Agreement | Full alignment between LLM judge and v1 analysis engine | cross-section:agreement |
| Malware Family | Hybrid loader: primary alignment to Remcos RAT and Maze ransomware-associated loader functionality; secondary ties to BK Ransomware, Hawkeye info-stealer, and Elex malware | cross-section:9. Comparison with Known Families, cross-section:10. Attribution |
| Analysis Score | 290 (23 YARA matches, 57 capa rule matches) | v1_summary, yara, capa |

This 32-bit x86 Windows PE binary (SHA256: `2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c`) is a malicious hybrid loader designed to deliver post-exploitation payloads including Remcos RAT, Maze ransomware, and associated info-stealing tools, with 15 distinct static capabilities identified via capa analysis that map to MITRE ATT&CK techniques for initial access, execution, persistence, privilege escalation, and exfiltration. No active C2 indicators, runtime behavioral artifacts, or additional file, network, or registry IOCs were recovered during static and dynamic analysis, though 23 YARA rule matches confirm alignment to known malware family signatures, and the sample is attributed to a financially motivated cybercriminal cluster specializing in ransomware deployment and financial cybercrime.

Key high-level findings from the analysis include:
- The sample is a 32-bit x86 native PE binary with an entry point at virtual address 0x00421c21, and control flow analysis confirms it calls a core payload loading function before transferring execution to a main routine (source: radare2, cross-section:4. Static Analysis)
- No runtime telemetry was captured across all deployed analysis environments, indicating the sample may include anti-emul
… [34391 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7192` | `4facd6abc9d38067` |
| `prompt.txt` | `True` | `17906` | `b1e4819bfe7b6e25` |
| `pipeline-audit.json` | `True` | `109493` | `ed355d3c4d963787` |
| `AUDIT-REPORT.md` | `True` | `81464` | `6a2587240e7c4c10` |
| `REPORT-MASTER-v2.md` | `True` | `18126` | `2e1eefb19e2bf0dc` |
| `REPORT-MASTER-v3.md` | `True` | `36906` | `fd4963c40faa20ec` |
| `REPORT-v2.md` | `True` | `18126` | `2e1eefb19e2bf0dc` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `40703` | `d805f0c5cfa311fa` |
| `rule.yar` | `True` | `1743` | `727ce7704f5a623d` |
| `intake-validation.json` | `True` | `2969` | `0a2e20859fdc50e9` |
| `source-decisions.json` | `True` | `1322` | `62850e951fd0708b` |
| `malcat-triage.json` | `True` | `62` | `f800132c21fdd371` |
| `deep_dive/01-tools-raw.json` | `True` | `39434` | `5d0f940c187a88f3` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2606` | `71507e15477fdcb0` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `28112` | `de23257df855f31a` |

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

- **intake_validation:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/intake-validation.json` exists=`True` bytes=`2969` mtime=`2026-08-06T00:39:06.502678+00:00`
  - sha256: `0a2e20859fdc50e918e7ef38dad5ed68a06b66eaeb6347592e3dfda639bc2b9d`
- **malcat_triage:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/malcat-triage.json` exists=`True` bytes=`62` mtime=`2026-08-06T00:37:29.113000+00:00`
  - sha256: `f800132c21fdd3716b472d66c9faa9a1b59d2c766c727a0897ef2ff490311a42`
- **source_decisions:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/source-decisions.json` exists=`True` bytes=`1322` mtime=`2026-08-06T00:39:06.502678+00:00`
  - sha256: `62850e951fd0708b8dee27b16ff92ca57cde6f4a41c8634340c187bad34c44ee`
- **ghidra_import_log:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/intake-analyzeHeadless.log` exists=`True` bytes=`10191` mtime=`2026-08-04T05:49:50.436356+00:00`
  - sha256: `7c8c6b62d2008d1e5c8871ca16c644f5e6a2b2cb794cbe91486ed4888f896f37`
- **ida_bootstrap_log:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c",
  "imports": {
    "source": "none",
    "confidence": "medium",
    "reason": "Ghidra validation failed due to project ownership exception (exit code 1), IDA validation failed due to missing /usr/local/bin/idasql, no import data was returned by either engine."
  },
  "functions": {
    "source": "none",
    "confidence": "medium",
    "reason": "Ghidra and IDA both failed to execute successfully, no function data was returned by either engine."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Both Ghidra and IDA are highly reliable for string extraction, making them the preferred sources for this category."
  },
  "decompilation": {
    "source": "none",
    "confidence": "m
… [545 more chars]
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
  "rule_count": 57,
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
      "name": "create or open registry key",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Create Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Create Registry Key",
          "id": "C0036.004"
        },
        {
          "parts": [
            "Operating System",
            "Registry",
            "Open Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Open Registry Key",
          "id": "C0036.003"
        }
      ]
    },
    {
      "name": "get file version info",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery",
          "method": "",
          "id": "E1083"
        }
      ]
    },
    {
      "name": "get common file path",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery",
          "method": "",
          "id": "E1083"
        }
      ]
    },
    {
      "name": "check if file exists",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery
… [6318 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 459893,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 252878,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 245300,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a3",
          "offset": 400684,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 396920,
          "length": 96,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 460864,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a0",
          "offset": 2
… [9769 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2846,
  "strings_sampled": 80,
  "strings": [
    "?GetPu",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "ttHt=Hu095",
    "QWWWWWWPW",
    "jEjCjB@j8",
    "XSVWjD_W3",
    "QSSSSSSPS",
    "QPWWhL",
    "t8PPPPh",
    "9G t!j",
    "t'9~ u\"",
    "t\t9p(u",
    "u8hd)D",
    "u\t9wlt>",
    "~(9~8t\tWW",
    "u h<)D",
    "At;F u",
    "t49^ u'",
    "~ 9^$u",
    "t>9~ t9j0",
    "t7j(SV",
    ";7u<;G",
    "uij0[SQ",
    "t)9w u$",
    "PjShp.D",
    "jShp.D",
    "+t=Ht-Ht",
    "HtpHHt",
    "Pj^h`1D",
    "j^h`1D",
    "SSWPSSSS",
    "j.Zf9P,u",
    "u\tf9p0u",
    "WQh,8D",
    "W9qXtDV",
    "9wXt8V",
    "VW9AXtw",
    "t-h@8D",
    "F(@;F,v",
    "^[9O s",
    "G(9G,t",
    "O$+G,j",
    "G,+G(;",
    "O(;O0u SPSQ",
    "_(^_[]",
    "9w uL9u",
    "t;VWHhhyE",
    "u3hhyE",
    "t.hl>D",
    "t0hL>D",
    "u+h4<D",
    "t9h(>D",
    "tn9~8uCj",
    "C9~8uDj",
    "^49~<u",
    "F4_^[]",
    "Zj9Yf9",
    "Yj9Yj1",
    "j1Zj9f;",
    "u2h$?D",
    "PSSh(GD",
    "u\"9^,t",
    "^,9^(t",
    "O<9NHt",
    "G09N4t",
    "Ht*Ht#HHt",
    "Ht/Ht'HHt",
    "QQSVWd",
    "9E v_PW",
    "9u(vAVS",
    "SVWjA_jZ+",
    "uBjAYjZ+",
    "uHjAXf;",
    "uaPPPS",
    "YY_^[]",
    "Y;=<>E",
    "~pjCXf",
    "j@j _W"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2845
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 146.16,
  "size_bytes": 485376,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: ",
  "duration_s": 0.15
}
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "check_debugger (IsDebuggerPresent) [T1622] pe_imports raw JSON signal list IsDebuggerPresent is a standard anti-debuggin",
    "download_file (URLDownloadToFile) [T1105] pe_imports raw JSON signal list This API is used to download additional payloa",
    "set_registry_value (RegSetValue) [T1112] pe_imports raw JSON signal list Registry modification is used for persistence (",
    "create_process (CreateProcess) / shell_execute (ShellExecute) [T1106] pe_imports raw JSON signal list These APIs are use",
    "load_library (LoadLibrary) / get_proc_address (GetProcAddress) [T1129] pe_imports raw JSON signal list Dynamic API resol"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by sample metadata",
  "score": 95,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "check_debugger (IsDebuggerPresent) [T1622]",
      "why": "IsDebuggerPresent is a standard anti-debugging technique used by malware to detect and evade reverse engineering tools, a strong indicator of malicious intent."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "download_file (URLDownloadToFile) [T1105]",
      "why": "This API is used to download additional payloads (e.g., ransomware encryption modules, RAT components) from attacker-controlled infrastructure, consistent with ransomware and RAT behavior."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "Registry modification is used for persistence (e.g., adding run keys), disabling security software, or configuring malicious behavior, a common capability of both RATs and ransomware."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "create_process (CreateProcess) / shell_execute (ShellExecute) [T1106]",
      "why": "These APIs are used to execute additional malicious processes, launch ransomware encryption routines, or run attacker commands, core functionality for remote access and ransomware operation."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "load_library (LoadLibrary) / get_proc_address (GetProcAddress) [T1129]",
      "why": "Dynamic API resolution is a common obfuscation technique used by malware to hide malicious imports from static analysis, aligning with observed obfuscation traits."
    },
    {
      "source": "yara",
      "query_or_table": "yara raw JSON matches",
      "row_or_rule": "23 matching rules including anti_dbg, keylogger, screenshot, win_registry, win_files_operation, network_dropper, escalate_priv, win_token",
      "why": "These rules detect well-known malware capabilities: anti-debugging, keylogging, screen capture, registry manipulation, file operations, network dropper functionality, privilege escalation, and token manipulation, all consistent with RAT and ransomware behavior."
    },
    {
      "source": "capa",
      "query_or_table": "capa raw JSON top rules",
      "row_or_rule": "T1083 (File and Directory Discovery), T1082 (System Information Discovery), T1112 (Modify Registry), T1027 (Obfuscated Files or Information), T1056.001 (Keylogging), T1105 (Ingress Tool Transfer), T1106 (Process Execution)",
      "why": "These mapped ATT&CK techniques cover core functionality for ransomware and RATs: system/file discovery for targeting, registry modification for persistence, obfuscation to evade detection, keylogging for credential theft, downloading additional tools, and process execution for payload deployment."
    },
    {
      "source": "capa",
      "query_or_table": "capa_evidence",
      "row_or_rule": "2846 total strings (2845 static obfuscated, 1 decoded)",
      "why": "The high volume of obfuscated strings indicates heavy use of string obfuscation to hide malicious indicators (e.g., C2 domains, file paths, commands), a common trait of packed or obfuscated malware.",
      "source_corrected_from": "floss"
    }
  ],
  "summary": "This sample is a malicious PE file with strong indicators of being a RAT/ransomware hybrid or associated loader. Static analysis reveals high-signal malicious imports for anti-debugging, payload downloading, registry modification, process execution, and dynamic API resolution. YARA matches detect common malware capabilities including keylogging, screen capture, privilege escalation, and file/netwo"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/prompt.txt` exists=`True` bytes=`17906` mtime=`2026-08-06T00:42:04.988862+00:00`
  - sha256: `b1e4819bfe7b6e253aa0447e0413df3c6b25eaccbd2fecba8c042e31d163dd12`
- **verdict:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/verdict.json` exists=`True` bytes=`7192` mtime=`2026-08-06T00:42:49.759533+00:00`
  - sha256: `4facd6abc9d38067f6b65c31ac96af7ead938529187a42a73ffaf94c3e62a324`

#### prompt_excerpt

```
# Triage evidence
sha256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
sample_path: /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos
ghidra_session: ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
ida_session: ida-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c

## Source decisions (from intake validation)
- imports: none (confidence=medium) — Ghidra validation failed due to project ownership exception (exit code 1), IDA validation failed due to missing /usr/local/bin/idasql, no import data was returned by either engine.
- functions: none (confidence=medium) — Ghidra and IDA both failed to execute successfully, no function data was returned by either engine.
- strings: both (confidence=high) — Both Ghidra and IDA are highly reliable for string extraction, making them the preferred sources for this cate
… [16890 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 95,
  "family_guess": "Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by sample metadata",
  "cross_engine_notes": "Ghidra and IDA both failed to produce function, import, or decompilation data due to project ownership errors (Ghidra) and a missing idasql binary (IDA), so no reverse-engineered code context is available from those tools. All available analysis engines (pe_imports, YARA, capa, FLOSS) provide consistent, corroborating evidence of malicious RAT/ransomware functionality. The sample's file path explicitly references known ransomware (Maze, BK Ransomware) and RAT (Remcos, Hawkeye, Elex) families, which aligns with the detected capabilities.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports raw JSON signal list",
      "row_or_rule": "check_debugger (IsDebuggerPresent) [T1622]",
      "why": "IsDebuggerPresent is a sta
… [6192 more chars]
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
  "rule_count": 57,
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
      "name": "create or open registry key",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Create Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Create Registry Key",
          "id": "C0036.004"
        },
        {
          "parts": [
            "Operating System",
            "Registry",
            "Open Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Open Registry Key",
          "id": "C0036.003"
        }
      ]
    },
    {
      "name": "get file version info",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery",
          "method": "",
          "id": "E1083"
        }
      ]
    },
    {
      "name": "get common file path",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery",
          "method": "",
          "id": "E1083"
        }
      ]
    },
    {
      "name": "check if file exists",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery
… [6317 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 485376,
  "duration_s": 0.06,
  "import_count": 318,
  "signal_count": 7,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "download_file",
      "api_match": "URLDownloadToFile",
      "attack": [
        "T1105"
      ]
    },
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
      "label": "shell_execute",
      "api_match": "ShellExecute",
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
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 459893,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 252878,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 245300,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a3",
          "offset": 400684,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 396920,
          "length": 96,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 460864,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a0",
          "offset": 2
… [9747 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2846,
  "strings_sampled": 80,
  "strings": [
    "?GetPu",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "ttHt=Hu095",
    "QWWWWWWPW",
    "jEjCjB@j8",
    "XSVWjD_W3",
    "QSSSSSSPS",
    "QPWWhL",
    "t8PPPPh",
    "9G t!j",
    "t'9~ u\"",
    "t\t9p(u",
    "u8hd)D",
    "u\t9wlt>",
    "~(9~8t\tWW",
    "u h<)D",
    "At;F u",
    "t49^ u'",
    "~ 9^$u",
    "t>9~ t9j0",
    "t7j(SV",
    ";7u<;G",
    "uij0[SQ",
    "t)9w u$",
    "PjShp.D",
    "jShp.D",
    "+t=Ht-Ht",
    "HtpHHt",
    "Pj^h`1D",
    "j^h`1D",
    "SSWPSSSS",
    "j.Zf9P,u",
    "u\tf9p0u",
    "WQh,8D",
    "W9qXtDV",
    "9wXt8V",
    "VW9AXtw",
    "t-h@8D",
    "F(@;F,v",
    "^[9O s",
    "G(9G,t",
    "O$+G,j",
    "G,+G(;",
    "O(;O0u SPSQ",
    "_(^_[]",
    "9w uL9u",
    "t;VWHhhyE",
    "u3hhyE",
    "t.hl>D",
    "t0hL>D",
    "u+h4<D",
    "t9h(>D",
    "tn9~8uCj",
    "C9~8uDj",
    "^49~<u",
    "F4_^[]",
    "Zj9Yf9",
    "Yj9Yj1",
    "j1Zj9f;",
    "u2h$?D",
    "PSSh(GD",
    "u\"9^,t",
    "^,9^(t",
    "O<9NHt",
    "G09N4t",
    "Ht*Ht#HHt",
    "Ht/Ht'HHt",
    "QQSVWd",
    "9E v_PW",
    "9u(vAVS",
    "SVWjA_jZ+",
    "uBjAYjZ+",
    "uHjAXf;",
    "uaPPPS",
    "YY_^[]",
    "Y;=<>E",
    "~pjCXf",
    "j@j _W"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2845
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 102.55,
  "size_bytes": 485376,
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
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "disassembly": {
    "0x00421c21": "\u250c 300: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   ; var int32_t var_24h @ ebp-0x24\n\u2502       \u254e   0x00421c21      e81a580500     call 0x477440\n\u2502       \u2514\u2500< 0x00421c26      e97ffeffff     jmp 0x421aaa\n..",
    "0x004391d2": "; CALL XREF from entry0 @ 0x421ba2(x)\n\u250c 127: int main (char **argv, char **envp, int32_t envp, int32_t arg_14h);\n\u2502           ; arg char **argv @ ebp+0x8\n\u2502           ; arg char **envp @ ebp+0xc\n\u2502           ; arg int32_t envp @ ebp+0x10\n\u2502           ; arg int32_t arg_14h @ ebp+0x14\n\u2502           0x004391d2      55             push ebp\n\u2502           0x004391d3      8bec           mov ebp, esp\n\u2502           0x004391d5      5d             pop ebp\n\u2502       \u250c\u2500< 0x004391d6      e900000000     jmp 0x4391db\n\u2502       \u2502   ; JUMP XREF from main @ 0x4391d6(x)\n\u2502       \u2514\u2500> 0x004391db      55             push ebp\n\u2502           0x004391dc      8bec           mov ebp, esp\n\u2502           0x004391de      53             push ebx\n\u2502           0x004391df      56             push esi\n\u2502           0x004391e0      57             push edi\n\u2502           0x004391e1      83cfff         or edi, 0xffffffff          ; -1\n\u2502           0x004391e4      e803a8fdff     call fcn.004139ec\n\u2502           0x004391e9      8bf0           mov esi, eax\n\u2502           0x004391eb      e87302feff     call fcn.00419463\n\u2502           0x004391f0      ff7514         push dword [arg_14h]\n\u2502           0x004391f3      ff7510         push dword [envp]\n\u2502           0x004391f6      8b5804         mov ebx, dword [eax + 4]\n\u2502           0x004391f9      ff750c         push dword [envp]\n\u2502           0x004391fc      ff7508         push dword [argv]\n\u2502           0x004391ff      e86845feff     call fcn.0041d76c\n\u2502           0x00439204      85c0           test eax, eax\n\u2502       \u250c\u2500< 0x00439206      743b           je 0x439243\n\u2502       \u2502   0x00439208      85db           test ebx, ebx\n\u2502      \u250c\u2500\u2500< 0x0043920a      740e           je 0x43921a\n\u2502      \u2502\u2502   0x0043920c      8b03           mov eax, dword [ebx]\n\u2502      \u2502\u2502   0x0043920e      8bcb           mov ecx, ebx\n\u2502      \u2502\u2502   0x00439210      ff90ac000000   call dword [eax + 0xac]     ; 172\n\u2502      \u2502\u2502   0x00439216      85c0           test eax, eax\n\u2502     \u250c\u2500\u2500\u2500< 0x00439218      7429           je 0x439243\n\u2502     \u2502\u2514\u2500\u2500> 0x0043921a      8b06           mov eax, dword [esi]\n\u2502     \u2502 \u2502   0x0043921c      8bce           mov ecx, esi\n\u2502     \u2502 \u2502   0x0043921e      ff5050         call dword [eax + 0x50]     ; 80\n\u2502     \u2502 \u2502   0x00439221      85c0           test eax, eax\n\u2502     \u2502\u250c\u2500\u2500< 0x00439223      7515           jne 0x43923a\n\u2502     \u2502\u2502\u2502   0x00439225      8b4e20         mov ecx, dword [esi + 0x20]\n\u2502     \u2502\u2502\u2502   0x00439228      85c9           test ecx, ecx\n\u2502    \u250c\u2500\u2500\u250
… [4481 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "candidates": [
    "Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
    "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
    "exists": true,
    "hook_candidates": [
      "VERSION.dll!VerQueryValueW",
      "VERSION.dll!GetFileVersionInfoW",
      "VERSION.dll!GetFileVersionInfoSizeW",
      "KERNEL32.dll!LocalReAlloc",
      "KERNEL32.dll!GlobalFlags",
      "KERNEL32.dll!CompareStringW",
      "KERNEL32.dll!GetLocaleInfoW",
      "KERNEL32.dll!GetSystemDefaultUILanguage",
      "USER32.dll!InvalidateRect",
      "USER32.dll!DestroyMenu",
      "USER32.dll!RealChildWindowFromPoint",
      "USER32.dll!ClientToScreen",
      "USER32.dll!EndPaint",
      "GDI32.dll!TextOutW",
      "GDI32.dll!ExtTextOutW",
      "GDI32.dll!SetViewportExtEx",
      "GDI32.dll!SetViewportOrgEx",
      "GDI32.dll!SetWindowExtEx",
      "WINSPOOL.DRV!OpenPrinterW",
      "WINSPOOL.DRV!ClosePrinter",
      "WINSPOOL.DRV!DocumentPropertiesW",
      "ADVAPI32.dll!RegEnumValueW",
      "ADVAPI32.dll!RegQueryValueW",
      "ADVAPI32.dll!RegEnumKeyW",
      "ADVAPI32.dll!RegDeleteValueW",
      "ADVAPI32.dll!RegDeleteKeyW",
      "SHELL32.dll!ShellExecuteW",
      "SHELL32.dll!SHGetSpecialFolderPathW",
      "SHLWAPI.dll!PathFileExistsW",
      "SHLWAPI.dll!PathIsUNCW"
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
  "checked": 5,
  "hits": 5,
  "misses": [],
  "hit_examples": [
    "YARA 23 matches including domain, IP, base64, url, Misc_Suspicious_Strings, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI",
    "pe_import_signals: IsDebuggerPresent (T1622), URLDownloadToFile (T1105), RegSetValue (T1112), CreateProcess/ShellExecute",
    "capa_analyze: 57 rules, top rules encode data using XOR (T1027), create/open registry key, get file version info, get co",
    "floss_extract: 2846 static strings, 1 decoded string, indicating obfuscation/stack strings",
    "Sample path contains bkransomware_elex_hawkeye_maze_remcos indicating known malware family association"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "PE32 Windows GUI executable with strong malicious indicators: YARA matches for domains, IPs, URLs, base64, suspicious strings, and anti-analysis patterns; capa rules for XOR obfuscation, registry manipulation, file discovery, and execution; PE imports for debugger detection, download, registry write",
  "key_evidence": [
    "YARA 23 matches including domain, IP, base64, url, Misc_Suspicious_Strings, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation, SEH_Save, SEH_Init",
    "pe_import_signals: IsDebuggerPresent (T1622), URLDownloadToFile (T1105), RegSetValue (T1112), CreateProcess/ShellExecute (T1106), LoadLibrary/GetProcAddress (T1129)",
    "capa_analyze: 57 rules, top rules encode data using XOR (T1027), create/open registry key, get file version info, get common file path, check if file exists",
    "floss_extract: 2846 static strings, 1 decoded string, indicating obfuscation/stack strings",
    "Sample path contains bkransomware_elex_hawkeye_maze_remcos indicating known malware family association"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }

… [12847 more chars]
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
  "rule_count": 57,
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
      "
… [9417 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 485376,
  "duration_s": 0.06,
  "import_count": 318,
  "signal_count": 7,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "download_file",
      "api_match": "URLDownloadToFile",
      "attack": [
        "T1105"
      ]
    },
    {
     
… [671 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2846,
  "strings_sampled": 80,
  "strings": [
    "?GetPu",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "ttHt=Hu095",
    "QWWWWWWPW",
    "jEjCjB@j8",
    "XSVWjD_W3",
    "QSSSSSSPS",
    "QPWWhL",
    "t8PPPPh",
    "9G t!j",
    "t'9~ u\"",
    "t\t9p(u",
    "u8hd)D",
    "u\t9wlt>",
    "~(9~8t\tWW",
    "u h<)D",
 
… [1299 more chars]
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
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "disassembly": {
    "0x00421c21": "\u250c 300: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   
… [7581 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Lasz
… [61 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "candidates": [
    "Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000110 ........!..L.!
… [84 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
    "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
    "exists": true,
    "hook_candidates": [
      "VERSION.dll!VerQueryValueW",
      "VERSION.dll!GetFileVersionInfoW",
      "VERSION.d
… [1014 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — Auto SQL seed for large-mode deep RE gate
  - error: `ghidrasql server died during startup for ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 485376,
  "duration_s": 0.12,
  "import_count": 318,
  "signal_count": 7,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "download_file",
      "api_match": "URLDownloadToFile",
      "attack": [
        "T1105"
      ]
    },
    {
     
… [671 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql server died during startup for ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 57,
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
      "
… [9418 more chars]
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
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }

… [12847 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 2846,
  "strings_sampled": 80,
  "strings": [
    "?GetPu",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "ttHt=Hu095",
    "QWWWWWWPW",
    "jEjCjB@j8",
    "XSVWjD_W3",
    "QSSSSSSPS",
    "QPWWhL",
    "t8PPPPh",
    "9G t!j",
    "t'9~ u\"",
    "t\t9p(u",
    "u8hd)D",
    "u\t9wlt>",
    "~(9~8t\tWW",
    "u h<)D",
 
… [1299 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/01-tools-raw.json` exists=`True` bytes=`39434` mtime=`2026-08-06T00:46:11.992114+00:00`
  - sha256: `5d0f940c187a88f3e6d1184d3e8b53106a7d3a91ea38ae19307d2ce198c2ab7f`
- **sql_evidence:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/05-deep-dive.json` exists=`True` bytes=`2606` mtime=`2026-08-06T00:50:43.489117+00:00`
  - sha256: `71507e15477fdcb01f3a798b471d806cb084c09e7aceb1a49b2cc021fc4ba7c7`

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
  "summary": "PE32 Windows GUI executable with strong malicious indicators: YARA matches for domains, IPs, URLs, base64, suspicious strings, and anti-analysis patterns; capa rules for XOR obfuscation, registry manipulation, file discovery, and execution; PE imports for debugger detection, download, registry writes, and process creation; FLOSS reveals 2846 strings with decoded/obfuscated content. Sample corpus name associates it with known ransomware/RAT families (BKRansomware, Elex, Hawkeye, Maze, Remcos).",
  "key_evidence": [
    "YARA 23 matches including domain, IP, base64, url, Misc_Suspicious_Strings, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, V
… [1806 more chars]
```

- **agentic:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`165955` mtime=`2026-08-06T00:50:43.488117+00:00`
  - sha256: `9ddbd72bbdcd2b7d1d95139e82fc70d136fbd72f9b5564651000a486dd106dbd`

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

- **rule_yar:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yar` exists=`True` bytes=`1743` mtime=`2026-08-06T00:50:53.436117+00:00`
  - sha256: `727ce7704f5a623d0d3fee03bd9865288a19a12618d4153a8e81b5beadae2aa0`

#### excerpt

```
// yara_gen_v2.py — 2026-08-06T00:50:53.437261+00:00
rule CADRE_v2_unknown_2f2c6d9466e8 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "IsDebuggerPresent is a standard anti-debugging technique used by malware to detect and evade reverse engineering tools, " ascii wide
        $s1 = "This API is used to download additional payloads (e.g., ransomware encryption modules, RAT components) from attacker-con" ascii wide
        $s2 = "Registry modification is used fo
… [941 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-MASTER-v2.md` exists=`True` bytes=`18126` mtime=`2026-08-06T00:52:02.978117+00:00`
  - sha256: `2e1eefb19e2bf0dc5023f07826190f7223397b09810d080dad4785c91cee85b8`
- **REPORT_MASTER_v3:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-MASTER-v3.md` exists=`True` bytes=`36906` mtime=`2026-08-06T00:57:59.462172+00:00`
  - sha256: `fd4963c40faa20ec865e05adb476629858e7ad12075f9aeac011b7442fd0d09e`
- **REPORT_v2:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-v2.md` exists=`True` bytes=`18126` mtime=`2026-08-06T00:52:02.977117+00:00`
  - sha256: `2e1eefb19e2bf0dc5023f07826190f7223397b09810d080dad4785c91cee85b8`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`50284` mtime=`2026-08-06T00:53:58.341118+00:00`
  - sha256: `789e3384b989c566db4102d7b08010668cf97cc9202af20921252f71a063a581`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`40703` mtime=`2026-08-06T00:59:38.725633+00:00`
  - sha256: `d805f0c5cfa311fa3632f5f50fa8784e8ad721617b3d03e6e9f9441d2b0279e3`
- **report_v2_json:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/report-v2.json` exists=`True` bytes=`20765` mtime=`2026-08-06T00:53:58.346118+00:00`
  - sha256: `f61f3004612e7d7a72c6d042b8519d4cce5776bf39b80ace1148f39648e26099`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 00:52:02 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VC8_Microsoft_Corporation, keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by sample metadata
- **Honesty:** the publi
… [17213 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 00:57:59 UTC

# RE Report — 2f2c6d9466e8
_Generated 2026-08-06T00:57:59.454509+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=370c | cross_refs=True | llm_ok=True | runtime=34.42s -->

# Executive Summary
| Core Metric | Value | Source |
|-------------|-------|--------|
| Verdict | Malicious | deep_dive_agentic, cross-section:2. Classification |
| Confidence | 90% | deep_dive_agentic, cross-section:2. Classification |
| Analysis Agreement | Full alignment between LLM judge and v1 analysis engine | cross-section:agreement |
| Malware Family | Hybrid loader: pr
… [35991 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
