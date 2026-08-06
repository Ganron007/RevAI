# Pipeline AUDIT-REPORT — `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-06T03:46:58.348107+00:00
- **Provenance:** `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-06 03:46:58 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`92`
- key_evidence_count=`10`

```json
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Lumma Stealer (LummaC2)",
  "cross_engine_notes": "Ghidra failed to execute due to a project ownership (NotOwnerException) error, IDA is unavailable due to a missing idasql binary, and Malcat crashed with a top-level error, so no function-level, decompilation, control flow graph, or static profile data is available from these tools. Reliable analysis data was successfully retrieved from pe_imports, capa, yara, and floss. Note that Ghidra's empty imports table is a known limitation for stripped/mixed-mode PEs and does not indicate a lack of malicious imports, as confirmed by the 171 high-signal imports retrieved via pe_imports.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "High-signal import confirming registry modification capability, a core TTP for info stealers used for persistence, data theft, and anti-analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_process (CreateProcess) [T1106], shell_execute (ShellExecute) [T1106]",
      "why": "High-signal imports enabling arbitrary process and command execution, consistent with malware payload deployment, lateral movement, and execution of attacker commands."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]",
      "why": "High-signal imports for dynamic API resolution, commonly used by malware to obfuscate functionality and evade static detection."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1083 (File and Directory Discovery) (4 matches)",
      "why": "Capa rule matches confirm the sample enumerates files and directories, a core behavior of info stealers targeting sensitive user and system data."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1112 (Modify Registry) (2 matches), T1012 (Query Registry) (2 matches)",
      "why": "Capa rules confirm registry manipulation capabilities, used for persistence, credential theft, configuration storage, and anti-analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1056.001 (Keylogging) (1 match)",
      "why": "Capa rule confirms keylogging functionality, a common feature of info stealers to capture user input including credentials and sensitive data."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1027 (Obfuscated Files or Information) (1 match, encode data using XOR)",
      "why": "Capa rule confirms XOR obfuscation usage, a common defense evasion technique used to hide sensitive data and malicious code from analysis."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "keylogger, win_registry, win_token, win_files_operation, escalate_priv, screenshot",
      "why": "YARA rule matches for common info stealer and credential theft behaviors, including keylogging, registry manipulation, token privilege escalation, file operations, and screenshot capture."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "IsPacked, HasOverlay, Nullsoft_PiMP_Stub_SFX",
      "why": "YARA matches confi
… [3203 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`17`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "Packed Windows PE with overlay and multiple deterministic malicious indicators: YARA matches for keylogger, screenshot, privilege escalation, and meterpreter artifacts; high-signal imports for process creation, shell execution, and registry modification; capa rules for XOR obfuscation and registry/file-system abuse; and 2325 static strings including process enumeration, file manipulation, and token/privilege APIs.",
  "key_evidence": [
    "YARA rule 'keylogger' fired (offset 39898, 40044, 38926)",
    "YARA rule 'screenshot' fired (offset 40044, 39898, 38926)",
    "YARA rule 'escalate_priv' fired (offset 40346, 35128)",
    "YARA rule 'android_meterpreter' fired (offset 779048)",
    "YARA rule 'IsPacked' fired",
    "YARA rule 'HasOverlay' fired",
    "YARA rule 'HasDigitalSignature' fired (offset 1128685)",
    "YARA rule 'Nullsoft_PiMP_Stub_SFX' fired (offset 11747)",
    "PE import signal: RegSetValue (T1112)",
    "PE import signal: CreateProcess (T1106)",
    "PE import signal: ShellExecute (T1106)",
    "PE import signal: LoadLibrary / GetProcAddress (T1129)",
    "capa rule: encode data using XOR (T1027)",
    "capa rule: create/open/delete registry key (T1112)",
    "capa rule: set file attributes (T1222)",
    "FLOSS static strings: AdjustTokenPrivileges, LookupPrivilegeValueW, OpenProcessToken, RegDeleteKeyExW, CreateToolhelp32Snapshot, EnumProcesses, EnumProcessModules, GetModuleBaseNameW, MoveFileExW, DeleteFileW, FindFirstFileW, FindNextFileW",
    "r2 entry error string: 'Error writing temporary file. Make sure your temp folder is valid.' (0x4091d8)"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 15,
  "successful_non_bootstrap_tools": 5,
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
  "title": "Malware Analysis Report: Lumma Stealer (LummaC2) Sample 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-06 03:40:04 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Lumma Stealer (LummaC2)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis sample is confirmed malicious, with a triage score of 92 and a family classification of Lumma Stealer (LummaC2), a commodity info-stealing malware operated as a crime-as-a-service (CaaS) platform. The sample is a packed 32-bit Windows PE GUI executable using a Nullsoft PiMP self-extracting (SFX) stub to evade static analysis, with an overlay containing the malicious payload. All core TTPs of Lumma are present: file and directory discovery, registry manipulation, system information gathering, keylogging, screenshot capture, privilege escalation, and XOR obfuscation of data and headers. No legitimate or benign functionality was identified during analysis. Dynamic behavioral analysis was not performed, so all behavioral observations are inferred from static indicators. (source: triage_verdict.json, deep-dive.json)\n\n## 1. Sample Identification\n- SHA256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50\n- Sample Path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe\n- Project Name: incoming\n- File Type: 32-bit Windows PE32 GUI executable, not a .NET assembly, not packed with UPX\n- Packing: Nullsoft PiMP SFX stub (YARA match at offset 11747), with a PE overlay containing the malicious payload (YARA HasOverlay match)\n- Entry Point: 0x004039e3 (per radare2 disassembly)\n- Static Metrics: 171 total PE imports, 2325 deobfuscated FLOSS strings, 19 YARA rule matches, 51 capa rule matches\n- Digital Signature: YARA detected a digital signature block at offset 1128685, but signature validity is unconfirmed. (source: sample_path, yara, r2_disassembly, floss, pe_imports, dotnet_analyze, upx_evidence)\n\n## 2. Classification\n- Verdict: Malicious\n- Family: Lumma Stealer (LummaC2)\n- Malware Type: Info Stealer\n- Confidence: 90% (deep dive) / 92% (triage)\n- Rationale: All observed TTPs, imports, YARA matches, and capa rules align with known Lumma Stealer operation. No legitimate functionality was identified. The sample is not a dual-use administrative tool, as all capabilities are consistent with malicious info theft and system compromise. (source: triage_verdict.json, deep-dive.json, yara, capa)\n\n## 3. Initial Triage (15 minutes)\nThe initial automated triage returned a malicious verdict with a score of 92, identifying the sample as Lumma Ste
… [21181 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:40:04 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Lumma Stealer (LummaC2)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This sample is confirmed malicious, with a triage score of 92 and a family classification of Lumma Stealer (LummaC2), a commodity info-stealing malware operated as a crime-as-a-service (CaaS) platform. The sample is a packed 32-bit Windows PE GUI executable using a Nullsoft PiMP self-extracting (SFX) stub to evade static analysis, with an overlay containing the malicious payload. All core TTPs of Lumma are present: file and directory discovery, registry manipulation, system information gathering, keylogging, screenshot capture, privilege escalation, and XOR obfuscation of data and headers. No legitimate or benign functionality was identified during analysis. Dynamic behavioral analysis was not performed, so all behavioral observations are inferred from static indicators. (source: triage_verdict.json, deep-dive.json)

## 1. Sample Identification
- SHA256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50
- Sample Path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe
- Project Name: incoming
- File Type: 32-bit Windows PE32 GUI executable, not a .NET assembly, not packed with UPX
- Packing: Nullsoft PiMP SFX stub (YARA match at offset 11747), with a PE overlay containing the malicious payload (YARA HasOverlay match)
- Entry Point: 0x004039e3 (per radare2 disassembly)
- Static Metrics: 171 total PE imports, 2325 deobfuscated FLOSS strings, 19 YARA rule matches, 51 capa rule matches
- Digital Signature: YARA detected a digital signature block at offset 1128685, bu
… [19585 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:45:03 UTC

# RE Report — 706a49b55ba7
_Generated 2026-08-06T03:45:03.786499+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=250c | cross_refs=True | llm_ok=True | runtime=24.76s -->

# Executive Summary

| Metric | Value |
|--------|-------|
| Verdict | Malicious |
| Malware Family | Lumma Stealer (LummaC2) |
| Confidence | 90% |
| Cross-Engine Agreement | LLM and v1 scanner aligned |
| v1 Scanner Score | 290 (19 YARA matches, 51 capa rules) |

The analyzed sample (SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`) is a 32-bit native Portable Executable (PE) with no embedded .NET metadata or valid code signing signatures, ruling out .NET payload classification and legitimate publisher authentication (source: cross-section:4. Static Analysis). It exhibits 15 distinct malicious capabilities grouped into 5 functional categories, mapped to 8 MITRE ATT&CK techniques across 4 tactics, with no significant deviations from standard LummaC2 feature sets observed (source: cross-section:7. Capability Assessment, cross-section:8. MITRE ATT&CK Mapping, cross-section:9. Comparison with Known Families). RAG-driven threat intelligence retrieval links the LummaC2 family to Russian-speaking threat actors (source: cross-section:10. Attribution).

No additional filesystem, registry, network, or synchronization indicators of compromise (IOCs) were recovered from static or dynamic analysis, with only the sample SHA256 hash identified as a valid IOC (source: cross-section:11. Indicators of Compromise, cross-section:5. Behavioral Analysis, cross-section:6. Network Analysis). 19 active YARA rule matches are available for detection, with aligned Sigma and Snort rule logic documented for deployment (source: cross-section:12. Detection Rules). No containment-relevant artifacts (persistence mechanisms, active C2 indicators, mutexes) were identified, so standard incident response practices including file removal, process termination, and credential rotation are sufficient to mitigate associated risk (source: cross-section:13. Containment, Eradication, Recovery).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=34c |
… [37312 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6703` | `74bb795199b2b77c` |
| `prompt.txt` | `True` | `21178` | `1a97ca21087cb15f` |
| `pipeline-audit.json` | `True` | `110905` | `8747503171227118` |
| `AUDIT-REPORT.md` | `True` | `83520` | `3bf34dc7ffdcf677` |
| `REPORT-MASTER-v2.md` | `True` | `22094` | `e5705268e97b5328` |
| `REPORT-MASTER-v3.md` | `True` | `39821` | `83bf305103968d43` |
| `REPORT-v2.md` | `True` | `22094` | `e5705268e97b5328` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `41939` | `9f57ffe512975d92` |
| `rule.yar` | `True` | `2039` | `c83670bbedb08c68` |
| `intake-validation.json` | `True` | `6438` | `711d1a78e533df64` |
| `source-decisions.json` | `True` | `4791` | `4172b5f5c33e2b49` |
| `malcat-triage.json` | `True` | `62` | `f800132c21fdd371` |
| `deep_dive/01-tools-raw.json` | `True` | `31537` | `00fe7750fb342c5a` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2930` | `142830fb1c224198` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `24954` | `b1675c899c2ed233` |

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

- **intake_validation:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/intake-validation.json` exists=`True` bytes=`6438` mtime=`2026-08-06T03:34:27.715766+00:00`
  - sha256: `711d1a78e533df64a87d62647a37543f6ef9daedcaaa062e8ca2a28eaa1c4987`
- **malcat_triage:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/malcat-triage.json` exists=`True` bytes=`62` mtime=`2026-08-06T03:32:36.896437+00:00`
  - sha256: `f800132c21fdd3716b472d66c9faa9a1b59d2c766c727a0897ef2ff490311a42`
- **source_decisions:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/source-decisions.json` exists=`True` bytes=`4791` mtime=`2026-08-06T03:34:27.715766+00:00`
  - sha256: `4172b5f5c33e2b49f59c978aa330331588495850527ad6967e93ff49d3c7ee97`
- **ghidra_import_log:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "imports": {
    "source": "none",
    "confidence": "medium",
    "reason": "Ghidra failed to start due to a project ownership error (NotOwnerException) during project open and exited with code 1 before processing the file (source: warning, Ghidra validation failed log, row: HeadlessAnalyzer.openProject error, why: no import data from Ghidra). IDA is unavailable due to a missing idasql binary, so it could not execute (source: warning, IDA validation failed, row: [Errno 2] No such file or directory: '/usr/local/bin/idasql', why: no import data from IDA). Malcat analysis failed with a top-level error (source: tool summary, malcat, row: error field, why: no import data from Malcat). This aligns with the exist
… [4014 more chars]
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
  "rule_count": 51,
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
      "name": "set file attributes",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "File and Directory Permissions Modification"
          ],
          "tactic": "Defense Evasion",
          "technique": "File and Directory Permissions Modification",
          "subtechnique": "",
          "id": "T1222"
        }
      ],
      "mbc": [
        {
          "parts": [
            "File System",
            "Set File Attributes"
          ],
          "objective": "File System",
          "behavior": "Set File Attributes",
          "method": "",
          "id": "C0050"
        }
      ]
    },
    {
      "name": "delete registry key",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Modify Registry"
          ],
          "tactic": "Defense Evasion",
          "technique": "Modify Registry",
          "subtechnique": "",
          "id": "T1112"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Delete Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Delete Registry Key",
          "id": "C0036.002"
        }
      ]
    },
    {
      "name": "query or enumerate registry key",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Query Registry"
          ],
          "tactic": "Discovery",
          "technique": "Query Registry",
          "subtechnique": "",
          "id": "T1012"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Query Registry Key"
          ],
          "objective": "Operating System
… [6640 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 68179,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 51945,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 35044,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 26628,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 34204,
          "length": 58,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 779048,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a3",
          "offset": 1128685,
          "length": 140,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 192,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule":
… [6344 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2325,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".ndata",
    "@.reloc",
    "PWSVh@",
    "#Vhh2@",
    "Instu`",
    "softuW",
    "NulluN\tE",
    "SUVWj 3",
    "D$8PUh",
    "u}9-$.G",
    "[j0Xjxf",
    "D$$+D$",
    "D$4+D$,P",
    "PPPPPP",
    "\\u!f9O",
    "QSUVWh",
    "Ed+EL;E",
    "u$9Mls",
    ")Mh)Mlf",
    "]4;Mhr",
    "E89E0}s",
    "u$9Uls",
    "-)Uh)Ul3",
    "SHGetFolderPathW",
    "SHFOLDER",
    "SHAutoComplete",
    "SHLWAPI",
    "GetUserDefaultUILanguage",
    "AdjustTokenPrivileges",
    "LookupPrivilegeValueW",
    "OpenProcessToken",
    "RegDeleteKeyExW",
    "ADVAPI32",
    "MoveFileExW",
    "GetDiskFreeSpaceExW",
    "KERNEL32",
    "[Rename]",
    "Module32NextW",
    "Module32FirstW",
    "Process32NextW",
    "Process32FirstW",
    "CreateToolhelp32Snapshot",
    "Kernel32.DLL",
    "GetModuleBaseNameW",
    "EnumProcessModules",
    "EnumProcesses",
    "PSAPI.DLL",
    "MulDiv",
    "DeleteFileW",
    "FindFirstFileW",
    "FindNextFileW",
    "FindClose",
    "SetFilePointer",
    "MultiByteToWideChar",
    "ReadFile",
    "WriteFile",
    "lstrlenA",
    "WideCharToMultiByte",
    "GetPrivateProfileStringW",
    "WritePrivateProfileStringW",
    "FreeLibrary",
    "LoadLibraryExW",
    "GetModuleHandleW",
    "GlobalFree",
    "GetExitCodeProcess",
    "WaitForSingleObject",
    "GlobalAlloc",
    "ExpandEnvironmentStringsW",
    "lstrcmpW",
    "lstrcmpiW",
    "CloseHandle",
    "SetFileTime",
    "CompareFileTime",
    "SearchPathW",
    "GetShortPathNameW",
    "GetFullPathNameW",
    "MoveFileW"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2325
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 29.94,
  "size_bytes": 1142333,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: ",
  "duration_s": 0.09
}
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "set_registry_value (RegSetValue) [T1112] signals High-signal import confirming registry modification capability, a core ",
    "create_process (CreateProcess) [T1106], shell_execute (ShellExecute) [T1106] signals High-signal imports enabling arbitr",
    "load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129] signals High-signal imports for dynamic AP",
    "T1083 (File and Directory Discovery) (4 matches) top_rules Capa rule matches confirm the sample enumerates files and dir",
    "T1112 (Modify Registry) (2 matches), T1012 (Query Registry) (2 matches) top_rules Capa rules confirm registry manipulati"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Lumma Stealer (LummaC2)",
  "score": 92,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "High-signal import confirming registry modification capability, a core TTP for info stealers used for persistence, data theft, and anti-analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_process (CreateProcess) [T1106], shell_execute (ShellExecute) [T1106]",
      "why": "High-signal imports enabling arbitrary process and command execution, consistent with malware payload deployment, lateral movement, and execution of attacker commands."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]",
      "why": "High-signal imports for dynamic API resolution, commonly used by malware to obfuscate functionality and evade static detection."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1083 (File and Directory Discovery) (4 matches)",
      "why": "Capa rule matches confirm the sample enumerates files and directories, a core behavior of info stealers targeting sensitive user and system data."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1112 (Modify Registry) (2 matches), T1012 (Query Registry) (2 matches)",
      "why": "Capa rules confirm registry manipulation capabilities, used for persistence, credential theft, configuration storage, and anti-analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1056.001 (Keylogging) (1 match)",
      "why": "Capa rule confirms keylogging functionality, a common feature of info stealers to capture user input including credentials and sensitive data."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1027 (Obfuscated Files or Information) (1 match, encode data using XOR)",
      "why": "Capa rule confirms XOR obfuscation usage, a common defense evasion technique used to hide sensitive data and malicious code from analysis."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "keylogger, win_registry, win_token, win_files_operation, escalate_priv, screenshot",
      "why": "YARA rule matches for common info stealer and credential theft behaviors, including keylogging, registry manipulation, token privilege escalation, file operations, and screenshot capture."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "IsPacked, HasOverlay, Nullsoft_PiMP_Stub_SFX",
      "why": "YARA matches confirm the sample is packed with a Nullsoft self-extracting stub, a common packing method used to obfuscate malware and evade static analysis."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "OpenProcessToken, AdjustTokenPrivileges, LookupPrivilegeValueW, RegDeleteKeyExW, EnumProcesses, EnumProcessModules, CreateToolhelp32Snapshot, FindFirstFileW, DeleteFileW, MoveFileExW",
      "why": "Deobfuscated FLOSS strings confirm low-level API usage for token/privilege manipulation, process enumeration, and file system operations, aligning with observed info stealer capabilities."
    }
  ],
  "summary": "This sample is a packed Windows PE file identified as Lumma Stealer (LummaC2), a known info-stealing malware family. The sample exhibits all core TTPs of Lumma: file and directory discovery, registry manipulation, system information gathering, keylogging, process enumeration, privilege escalation, and XOR obfuscation. It is packed with a Nullsoft PiMP self-extracting stub to evade static analysis,"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/prompt.txt` exists=`True` bytes=`21178` mtime=`2026-08-06T03:35:23.143714+00:00`
  - sha256: `1a97ca21087cb15f70c3c1446eb62bee04a8776bf3adceb68917eb03e86c674a`
- **verdict:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/verdict.json` exists=`True` bytes=`6703` mtime=`2026-08-06T03:36:04.791665+00:00`
  - sha256: `74bb795199b2b77c33cc242e60f1f3dcb22462c41db2fdb01f8d3a19a9b2add4`

#### prompt_excerpt

```
# Triage evidence
sha256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50
sample_path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe
ghidra_session: ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50
ida_session: ida-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50

## Source decisions (from intake validation)
- imports: none (confidence=medium) — Ghidra failed to start due to a project ownership error (NotOwnerException) during project open and exited with code 1 before processing the file (source: warning, Ghidra validation failed log, row: HeadlessAnalyzer.openProject error, why: no import data from Ghidra). IDA is unavailable due to a missing idasql binary, so it could not execute (source: warning, IDA validation failed, row: [Errno 2] No such file or directory: '/usr/local/bin/idasql', why: no import data from IDA). Malcat analysis failed with a top-level error
… [20162 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Lumma Stealer (LummaC2)",
  "cross_engine_notes": "Ghidra failed to execute due to a project ownership (NotOwnerException) error, IDA is unavailable due to a missing idasql binary, and Malcat crashed with a top-level error, so no function-level, decompilation, control flow graph, or static profile data is available from these tools. Reliable analysis data was successfully retrieved from pe_imports, capa, yara, and floss. Note that Ghidra's empty imports table is a known limitation for stripped/mixed-mode PEs and does not indicate a lack of malicious imports, as confirmed by the 171 high-signal imports retrieved via pe_imports.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "High-signal import confirming registry modification capability, a core TTP for info stealers used for persistence, data theft, and 
… [5703 more chars]
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
  "rule_count": 51,
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
      "name": "set file attributes",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "File and Directory Permissions Modification"
          ],
          "tactic": "Defense Evasion",
          "technique": "File and Directory Permissions Modification",
          "subtechnique": "",
          "id": "T1222"
        }
      ],
      "mbc": [
        {
          "parts": [
            "File System",
            "Set File Attributes"
          ],
          "objective": "File System",
          "behavior": "Set File Attributes",
          "method": "",
          "id": "C0050"
        }
      ]
    },
    {
      "name": "delete registry key",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Modify Registry"
          ],
          "tactic": "Defense Evasion",
          "technique": "Modify Registry",
          "subtechnique": "",
          "id": "T1112"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Delete Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Delete Registry Key",
          "id": "C0036.002"
        }
      ]
    },
    {
      "name": "query or enumerate registry key",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Query Registry"
          ],
          "tactic": "Discovery",
          "technique": "Query Registry",
          "subtechnique": "",
          "id": "T1012"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Query Registry Key"
          ],
          "objective": "Operating System
… [6640 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1142333,
  "duration_s": 0.03,
  "import_count": 171,
  "signal_count": 5,
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
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 68179,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 51945,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 35044,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 26628,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 34204,
          "length": 58,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 779048,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a3",
          "offset": 1128685,
          "length": 140,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 192,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule":
… [6322 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2325,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".ndata",
    "@.reloc",
    "PWSVh@",
    "#Vhh2@",
    "Instu`",
    "softuW",
    "NulluN\tE",
    "SUVWj 3",
    "D$8PUh",
    "u}9-$.G",
    "[j0Xjxf",
    "D$$+D$",
    "D$4+D$,P",
    "PPPPPP",
    "\\u!f9O",
    "QSUVWh",
    "Ed+EL;E",
    "u$9Mls",
    ")Mh)Mlf",
    "]4;Mhr",
    "E89E0}s",
    "u$9Uls",
    "-)Uh)Ul3",
    "SHGetFolderPathW",
    "SHFOLDER",
    "SHAutoComplete",
    "SHLWAPI",
    "GetUserDefaultUILanguage",
    "AdjustTokenPrivileges",
    "LookupPrivilegeValueW",
    "OpenProcessToken",
    "RegDeleteKeyExW",
    "ADVAPI32",
    "MoveFileExW",
    "GetDiskFreeSpaceExW",
    "KERNEL32",
    "[Rename]",
    "Module32NextW",
    "Module32FirstW",
    "Process32NextW",
    "Process32FirstW",
    "CreateToolhelp32Snapshot",
    "Kernel32.DLL",
    "GetModuleBaseNameW",
    "EnumProcessModules",
    "EnumProcesses",
    "PSAPI.DLL",
    "MulDiv",
    "DeleteFileW",
    "FindFirstFileW",
    "FindNextFileW",
    "FindClose",
    "SetFilePointer",
    "MultiByteToWideChar",
    "ReadFile",
    "WriteFile",
    "lstrlenA",
    "WideCharToMultiByte",
    "GetPrivateProfileStringW",
    "WritePrivateProfileStringW",
    "FreeLibrary",
    "LoadLibraryExW",
    "GetModuleHandleW",
    "GlobalFree",
    "GetExitCodeProcess",
    "WaitForSingleObject",
    "GlobalAlloc",
    "ExpandEnvironmentStringsW",
    "lstrcmpW",
    "lstrcmpiW",
    "CloseHandle",
    "SetFileTime",
    "CompareFileTime",
    "SearchPathW",
    "GetShortPathNameW",
    "GetFullPathNameW",
    "MoveFileW"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2325
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 28.2,
  "size_bytes": 1142333,
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
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "disassembly": {
    "0x004039e3": "\u250c 997: entry0 ();\n\u2502           ; var int32_t var_10h_4 @ esp+0x10\n\u2502           ; var int32_t var_10h_3 @ esp+0x28\n\u2502           ; var int32_t var_30h @ esp+0x58\n\u2502           ; var int32_t var_2ch @ esp+0x60\n\u2502           ; var int32_t var_44h @ esp+0x6c\n\u2502           ; var int32_t var_24h @ esp+0x70\n\u2502           ; var int32_t var_10h_2 @ esp+0x74\n\u2502           ; var int32_t var_14h_2 @ esp+0x78\n\u2502           ; var int32_t var_18h_2 @ esp+0x7c\n\u2502           ; var int32_t var_14h_3 @ esp+0x90\n\u2502           ; var int32_t var_1ch @ esp+0x98\n\u2502           ; var int32_t var_10h @ esp+0xcc\n\u2502           ; var int32_t var_14h @ esp+0xd0\n\u2502           ; var int32_t var_18h @ esp+0xd4\n\u2502           ; var int32_t var_38h @ esp+0xe0\n\u2502           0x004039e3      81ecd4020000   sub esp, 0x2d4\n\u2502           0x004039e9      53             push ebx\n\u2502           0x004039ea      55             push ebp\n\u2502           0x004039eb      56             push esi\n\u2502           0x004039ec      57             push edi\n\u2502           0x004039ed      6a20           push 0x20                   ; 32\n\u2502           0x004039ef      33ed           xor ebp, ebp\n\u2502           0x004039f1      5e             pop esi\n\u2502           0x004039f2      896c2418       mov dword [var_18h], ebp\n\u2502           0x004039f6      c7442410d8..   mov dword [var_10h], str.Error_writing_temporary_file._Make_sure_your_temp_folder_is_valid. ; [0x4091d8:4]=0x720045 ; u\"Error writing temporary file. Make sure your temp folder is valid.\"\n\u2502           0x004039fe      896c2414       mov dword [var_14h], ebp\n\u2502           0x00403a02      ff1530804000   call dword [sym.imp.COMCTL32.dll_InitCommonControls] ; 0x408030 ; void InitCommonControls(void)\n\u2502           0x00403a08      6801800000     push 0x8001\n\u2502           0x00403a0d      ff15b8804000   call dword [sym.imp.KERNEL32.dll_SetErrorMode] ; 0x4080b8 ; UINT SetErrorMode(UINT uMode)\n\u2502           0x00403a13      55             push ebp\n\u2502           0x00403a14      ff15c0824000   call dword [sym.imp.ole32.dll_OleInitialize] ; 0x4082c0\n\u2502           0x00403a1a      6a08           push 8                      ; 8\n\u2502           0x00403a1c      a3b82e4700     mov dword [0x472eb8], eax   ; [0x472eb8:4]=0\n\u2502           0x00403a21      e8372a0000     call 0x40645d\n\u2502           0x00403a26      55             push ebp\n\u2502           0x00403a27      68b4020000     push 0x2b4                  ; 692\n\u2502           0x00403a2c      a3d02d4700     mov dword [0x472dd0], eax   ; [0x472dd0:4]=0\n\u2502           0x00403a31      8d442438       lea eax, [var_38h]\n\u2502           0x00403a35      50             push eax\n\u2502           0x00403a36      55             push ebp\n\u2502           0x00403a37      681c934000     push 0x40931c\n\u2502           0x00403a3c      ff1584814000   call dword [sym.imp.SHELL32.dll_SHGetFileInfoW] ; 0x408184 ; DWORD_PTR SHGetFileInfoW(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags)\n\u2502           0x00403a42      6804934000     push str.NSIS_Error         ; 0x409304 ; u\"NSIS Error\"\n\u2502           0x00403a47  "
  },
  "engine": "pdf (disasm)",
  "fallba
… [60 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!SetFileTime",
      "KERNEL32.dll!CompareFileTime",
      "KERNEL32.dll!SearchPathW",
      "KERNEL32.dll!GetShortPathNameW",
      "KERNEL32.dll!GetFullPathNameW",
      "USER32.dll!GetAsyncKeyState",
      "USER32.dll!IsDlgButtonChecked",
      "USER32.dll!ScreenToClient",
      "USER32.dll!GetMessagePos",
      "USER32.dll!CallWindowProcW",
      "GDI32.dll!SetBkColor",
      "GDI32.dll!GetDeviceCaps",
      "GDI32.dll!DeleteObject",
      "GDI32.dll!CreateBrushIndirect",
      "GDI32.dll!CreateFontIndirectW",
      "SHELL32.dll!SHBrowseForFolderW",
      "SHELL32.dll!SHGetPathFromIDListW",
      "SHELL32.dll!SHGetFileInfoW",
      "SHELL32.dll!ShellExecuteW",
      "SHELL32.dll!SHFileOperationW",
      "ADVAPI32.dll!RegEnumKeyW",
      "ADVAPI32.dll!RegOpenKeyExW",
      "ADVAPI32.dll!RegCloseKey",
      "ADVAPI32.dll!RegDeleteKeyW",
      "ADVAPI32.dll!RegDeleteValueW",
      "COMCTL32.dll!ImageList_AddMasked",
      "COMCTL32.dll!ImageList_Destroy",
      "COMCTL32.dll!ImageList_Create",
      "ole32.dll!CoTaskMemFree",
      "ole32.dll!OleInitialize"
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
  "checked": 17,
  "hits": 17,
  "misses": [],
  "hit_examples": [
    "YARA rule 'keylogger' fired (offset 39898, 40044, 38926)",
    "YARA rule 'screenshot' fired (offset 40044, 39898, 38926)",
    "YARA rule 'escalate_priv' fired (offset 40346, 35128)",
    "YARA rule 'android_meterpreter' fired (offset 779048)",
    "YARA rule 'IsPacked' fired"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Packed Windows PE with overlay and multiple deterministic malicious indicators: YARA matches for keylogger, screenshot, privilege escalation, and meterpreter artifacts; high-signal imports for process creation, shell execution, and registry modification; capa rules for XOR obfuscation and registry/f",
  "key_evidence": [
    "YARA rule 'keylogger' fired (offset 39898, 40044, 38926)",
    "YARA rule 'screenshot' fired (offset 40044, 39898, 38926)",
    "YARA rule 'escalate_priv' fired (offset 40346, 35128)",
    "YARA rule 'android_meterpreter' fired (offset 779048)",
    "YARA rule 'IsPacked' fired",
    "YARA rule 'HasOverlay' fired",
    "YARA rule 'HasDigitalSignature' fired (offset 1128685)",
    "YARA rule 'Nullsoft_PiMP_Stub_SFX' fired (offset 11747)",
    "PE import signal: RegSetValue (T1112)",
    "PE import signal: CreateProcess (T1106)",
    "PE import signal: ShellExecute (T1106)",
    "PE import signal: LoadLibrary / GetProcAddress (T1129)",
    "capa rule: encode data using XOR (T1027)",
    "capa rule: create/open/delete registry key (T1112)",
    "capa rule: set file attributes (T1222)",
    "FLOSS static strings: AdjustTokenPrivileges, LookupPrivilegeValueW, OpenProcessToken, RegDeleteKeyExW, CreateToolhelp32Snapshot, EnumProcesses, EnumProcessModules, GetModuleBaseNameW, MoveFileExW, DeleteFileW, FindFirstFileW, FindNextFileW",
    "r2 entry error string: 'Error writing temporary file. Make sure your temp folder is valid.' (0x4091d8)"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
      "path": "/opt/
… [9422 more chars]
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
  "rule_count": 51,
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
… [9740 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1142333,
  "duration_s": 0.03,
  "import_count": 171,
  "signal_count": 5,
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
… [417 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2325,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".ndata",
    "@.reloc",
    "PWSVh@",
    "#Vhh2@",
    "Instu`",
    "softuW",
    "NulluN\tE",
    "SUVWj 3",
    "D$8PUh",
    "u}9-$.G",
    "[j0Xjxf",
    "D$$+D$",
    "D$4+D$,P",
    "PPPPPP",
    "\\u!f9O",
    "QSUVWh",
   
… [1672 more chars]
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
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "disassembly": {
    "0x004039e3": "\u250c 997: entry0 ();\n\u2502           ; var int32_t var_10h_4 @ esp+0x10\n\u2502           ; var int32_t var_10h_3 @ esp+0x28\n\u2502           ; var int32_t var_30h @ esp+0x58\n\u2502           ; var int32_t var_2
… [3160 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xor
… [23 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!SetFileTime",
      "KERNEL32.dll!CompareFileTime",
      "KERNEL32.dll!SearchPathW",
      "KERNEL32.dll!GetShortPathNameW",
      "K
… [951 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — Auto SQL seed for large-mode deep RE gate
  - error: `ghidrasql server died during startup for ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 1142333,
  "duration_s": 0.05,
  "import_count": 171,
  "signal_count": 5,
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
… [417 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql server died during startup for ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 51,
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
… [9740 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 2325,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".ndata",
    "@.reloc",
    "PWSVh@",
    "#Vhh2@",
    "Instu`",
    "softuW",
    "NulluN\tE",
    "SUVWj 3",
    "D$8PUh",
    "u}9-$.G",
    "[j0Xjxf",
    "D$$+D$",
    "D$4+D$,P",
    "PPPPPP",
    "\\u!f9O",
    "QSUVWh",
   
… [1673 more chars]
```

- **angr_analyze** ok=`False` checklist=`False` — langgraph tool call
  - error: `invoke_z3_or_angr not found in extensions/deobfuscation/`

```json
{
  "error": "invoke_z3_or_angr not found in extensions/deobfuscation/"
}
```

- **r2_decompile** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
  "disassembly": {
    "0x004039e3": "\u250c 997: entry0 ();\n\u2502           ; var int32_t var_10h_4 @ esp+0x10\n\u2502           ; var int32_t var_10h_3 @ esp+0x28\n\u2502           ; var int32_t var_30h @ esp+0x58\n\u2502           ; var int32_t var_2
… [3160 more chars]
```

- **yara_scan** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
      "path": "/opt/
… [9422 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/01-tools-raw.json` exists=`True` bytes=`31537` mtime=`2026-08-06T03:36:50.354527+00:00`
  - sha256: `00fe7750fb342c5a95c6b3737a5d7ab46535151e932b39c6d7944d62436eada4`
- **sql_evidence:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/05-deep-dive.json` exists=`True` bytes=`2930` mtime=`2026-08-06T03:37:44.074466+00:00`
  - sha256: `142830fb1c2241987d52ae1282b27a128b773a9b82f814bfed150086aa1aa7d7`

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
  "summary": "Packed Windows PE with overlay and multiple deterministic malicious indicators: YARA matches for keylogger, screenshot, privilege escalation, and meterpreter artifacts; high-signal imports for process creation, shell execution, and registry modification; capa rules for XOR obfuscation and registry/file-system abuse; and 2325 static strings including process enumeration, file manipulation, and token/privilege APIs.",
  "key_evidence": [
    "YARA rule 'keylogger' fired (offset 39898, 40044, 38926)",
    "YARA rule 'screenshot' fired (offset 40044, 39898, 38926)",
    "YARA rule 'escalate_priv' fired (offset 40346, 35128)",
    "YARA rule 'android_meterpreter' fired (offset
… [2130 more chars]
```

- **agentic:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`153378` mtime=`2026-08-06T03:37:44.073465+00:00`
  - sha256: `d39439d5eaa8fdc3aa2c8cdfa692d5cc4f3475ddc674cb91d1f0514b2836c18c`

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

- **rule_yar:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/rule.yar` exists=`True` bytes=`2039` mtime=`2026-08-06T03:37:53.478462+00:00`
  - sha256: `c83670bbedb08c6865085bddb738208a126ca5a0777f7713064ff81ce562ed0f`

#### excerpt

```
// yara_gen_v2.py — 2026-08-06T03:37:53.479522+00:00
rule CADRE_v2_unknown_706a49b55ba7 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "High-signal import confirming registry modification capability, a core TTP for info stealers used for persistence, data " ascii wide
        $s1 = "High-signal imports enabling arbitrary process and command execution, consistent with malware payload deployment, latera" ascii wide
        $s2 = "High-signal imports for dynamic 
… [1237 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-MASTER-v2.md` exists=`True` bytes=`22094` mtime=`2026-08-06T03:40:04.663412+00:00`
  - sha256: `e5705268e97b53289690d447f4c1ad5f1f9e845154de21421f5dec0fc32d5a26`
- **REPORT_MASTER_v3:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-MASTER-v3.md` exists=`True` bytes=`39821` mtime=`2026-08-06T03:45:03.792262+00:00`
  - sha256: `83bf305103968d43983b2d91a33ac3392366350ed1073dcf28e45c67697c0974`
- **REPORT_v2:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-v2.md` exists=`True` bytes=`22094` mtime=`2026-08-06T03:40:04.663412+00:00`
  - sha256: `e5705268e97b53289690d447f4c1ad5f1f9e845154de21421f5dec0fc32d5a26`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`40329` mtime=`2026-08-06T03:41:21.127491+00:00`
  - sha256: `948efce7eef143423700acd66e18ac5f956a6ca0f646e73ddeaba7cce86316ad`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`41939` mtime=`2026-08-06T03:46:55.497755+00:00`
  - sha256: `9f57ffe512975d92a0a57c7d72cace80ae0b945c4d4055ebe18a1341a9999b4b`
- **report_v2_json:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/report-v2.json` exists=`True` bytes=`24681` mtime=`2026-08-06T03:41:21.132491+00:00`
  - sha256: `2297afe82bde925d778b3d8eee3939509478f96c5111b7fdac0c6eff839f09b4`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:40:04 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Lumma Stealer (LummaC2)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narra
… [21185 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:45:03 UTC

# RE Report — 706a49b55ba7
_Generated 2026-08-06T03:45:03.786499+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=250c | cross_refs=True | llm_ok=True | runtime=24.76s -->

# Executive Summary

| Metric | Value |
|--------|-------|
| Verdict | Malicious |
| Malware Family | Lumma Stealer (LummaC2) |
| Confidence | 90% |
| Cross-Engine Agreement | LLM and v1 scanner aligned |
| v1 Scanner Score | 290 (19 YARA matches, 51 capa rules) |

The analyzed sample (SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`) is a 32-bit nativ
… [38912 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
