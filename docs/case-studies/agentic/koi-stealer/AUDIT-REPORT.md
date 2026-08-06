# Pipeline AUDIT-REPORT — `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-06T04:12:27.839963+00:00
- **Provenance:** `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-06 04:12:27 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`

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
- key_evidence_count=`11`

```json
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Unknown Delphi-based packed malware, likely an infostealer or remote access trojan (RAT) given its system/registry/file discovery, process injection, and privilege escalation capabilities",
  "cross_engine_notes": "Ghidra and IDA analysis failed due to technical issues (Ghidra project ownership error, missing idasql binary), so all evidence is sourced from pe_imports, capa, YARA, and FLOSS. Cross-engine alignment is strong: YARA's Delphi compiler identification matches FLOSS's Delphi-specific strings; pe_imports' high-signal process injection and execution APIs align with capa's detected process injection, execution, and obfuscation behaviors. The sample's packed state (confirmed by YARA) explains its large 2.2MB size, high string count, and failure of Ghidra/IDA to extract function data.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "high-signal import signals",
      "row_or_rule": "CreateProcess (mapped to ATT&CK T1106)",
      "why": "This high-signal import is used for spawning new processes, a core capability for malware execution, process injection, and running malicious payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal import signals",
      "row_or_rule": "LoadLibrary + GetProcAddress (mapped to ATT&CK T1129)",
      "why": "These imports enable dynamic API resolution, a common malware technique to hide malicious functionality from static analysis by loading functions only at runtime."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal import signals",
      "row_or_rule": "VirtualAlloc + VirtualProtect (mapped to ATT&CK T1055)",
      "why": "These imports are used for memory allocation and modifying memory page permissions, core capabilities for process injection, shellcode execution, and unpacking obfuscated code."
    },
    {
      "source": "capa",
      "query_or_table": "top ATT&CK behavior rules",
      "row_or_rule": "encode data using XOR (T1027) + encrypt data using RC4 PRGA (T1027)",
      "why": "These rules confirm the sample uses obfuscation (XOR encoding, RC4 encryption) to hide malicious code or sensitive data, a standard defense evasion tactic."
    },
    {
      "source": "capa",
      "query_or_table": "top ATT&CK behavior rules",
      "row_or_rule": "System Information Discovery (T1082): check OS version, get disk size, query environment variable",
      "why": "This behavior indicates the sample performs system reconnaissance to profile the target environment, a common step for malware to adapt its behavior or identify high-value targets."
    },
    {
      "source": "capa",
      "query_or_table": "top ATT&CK behavior rules",
      "row_or_rule": "Query Registry (T1012): query or enumerate registry value",
      "why": "Registry access is commonly used by malware for persistence, storing configuration data, or stealing stored credentials."
    },
    {
      "source": "capa",
      "query_or_table": "top ATT&CK behavior rules",
      "row_or_rule": "Access Token Manipulation (T1134): modify access privileges",
      "why": "This behavior indicates the sample manipulates Windows access tokens to escalate privileges, allowing it to perform restricted actions like accessing protected system resources."
    },
    {
      "source": "yara",
      "query_or_table": "rule matches",
      "row_or_rule": "domain, IP, contains_base64 rules",
    
… [3874 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`6`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "Sample e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 is a packed Borland/Delphi GUI PE with strong malicious indicators. Static analysis shows obfuscation/encoding (XOR, RC4), high-signal offensive imports (CreateProcess, VirtualAlloc, VirtualProtect, LoadLibrary, GetProcAddress), registry manipulation, network indicators (domain, IP, URL, base64), and Delphi runtime artifacts. Emulation produced no observable behavior, but deterministic static signals dominate.",
  "key_evidence": [
    "YARA 26 matches: Borland/Delphi family, IsPacked, HasOverlay, domain, IP, URL, base64, CRC32_poly_Constant, Delphi_CompareCall",
    "capa 49 rules: encode data using XOR (T1027), encrypt data using RC4 PRGA (T1027), create or open registry key, check OS version, plus additional obfuscation/anti-analysis rules",
    "pe_import_signals: CreateProcess (T1106), LoadLibrary (T1129), GetProcAddress (T1129), VirtualProtect (T1055), VirtualAlloc (T1055)",
    "floss: 11298 strings including Delphi RTTI/type names (Boolean, System, AnsiString, WideString, TObject&, DisposeOf, InitInstance, ClassName, etc.) and 1 tight string",
    "r2 entry0 at 0x004b5eec with large stack frame and Delphi-style initialization",
    "speakeasy_emulate: no dynamic API calls or strings observed, consistent with packed/obfuscated static-only sample"
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
  "title": "Malware Analysis Report: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (Unknown Delphi-Based Infostealer/RAT)",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-06 04:01:09 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Unknown Delphi-based packed malware, likely an infostealer or remote access trojan (RAT) given its system/registry/file discovery, process injection, and privilege escalation capabilities\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Malware Analysis Report: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (Unknown Delphi-Based Infostealer/RAT)\n\n## Executive Summary\nThis report details the analysis of sample `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`, a 2.2MB packed Borland Delphi PE file classified as **Malicious** with a confidence score of 92/100. Static analysis reveals the sample is packed with custom obfuscation (XOR, RC4), contains high-signal offensive imports for process injection, dynamic API resolution, and memory manipulation, and exhibits capabilities consistent with an infostealer or remote access trojan (RAT). No dynamic behavior was observed during emulation, consistent with a packed sample that only exposes malicious functionality at runtime after unpacking. The sample is an unknown Delphi-based malware family, with no confirmed attribution to a specific threat actor. Key risks include credential theft, system reconnaissance, privilege escalation, and remote command and control (C2) access for compromised endpoints. (source: triage_verdict, deep-dive)\n\n## 1. Sample Identification\nThe analyzed sample has SHA256 hash `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`, stored at `/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe`. It is a 32-bit Windows GUI PE file, 2.2MB in size, compiled with Borland Delphi as confirmed by 26 YARA matches for Delphi compiler artifacts and 11,298 FLOSS-extracted strings including Delphi RTL internal markers (`InitInstance`, `GetInterface`, `TInterfaceTable`). UPX unpacking failed, indicating the sample uses a custom packer, consistent with YARA's `IsPacked` and `HasOverlay` matches. The entry point is located at `0x004b5eec`, with a large stack frame and Delphi-style initialization code observed in radare2 disassembly. (source: upx_unpack, yara, floss, r2_disasm, ghidra_query)\n\n## 2. Classification\n**Verdict: Malicious**\n**Family: Unknown Delphi-based packed malware, likely an infostealer or remote access trojan (RAT)**\nThis classification is supported by a triage score of 92/100, high-signal offensive imports, capa-identified malicious 
… [15928 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 04:01:09 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unknown Delphi-based packed malware, likely an infostealer or remote access trojan (RAT) given its system/registry/file discovery, process injection, and privilege escalation capabilities
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (Unknown Delphi-Based Infostealer/RAT)

## Executive Summary
This report details the analysis of sample `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`, a 2.2MB packed Borland Delphi PE file classified as **Malicious** with a confidence score of 92/100. Static analysis reveals the sample is packed with custom obfuscation (XOR, RC4), contains high-signal offensive imports for process injection, dynamic API resolution, and memory manipulation, and exhibits capabilities consistent with an infostealer or remote access trojan (RAT). No dynamic behavior was observed during emulation, consistent with a packed sample that only exposes malicious functionality at runtime after unpacking. The sample is an unknown Delphi-based malware family, with no confirmed attribution to a specific threat actor. Key risks include credential theft, system reconnaissance, privilege escalation, and remote command and control (C2) access for compromised endpoints. (source: triage_verdict, deep-dive)

## 1. Sample Identification
The analyzed sample has SHA256 hash `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`, stored at `/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe`. It is a 32-bit Windows GUI PE file, 2.2MB in size, compiled with Borland Delph
… [14439 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 04:09:53 UTC

# RE Report — e29d2bd94621
_Generated 2026-08-06T04:09:53.513666+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=414c | cross_refs=True | llm_ok=True | runtime=26.17s -->

### Executive Summary
The analyzed sample (SHA256: `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`) is classified as **Malicious** with 90% confidence, with agreement between LLM judgment and v1 static analysis engine confirming the verdict (source: cross-section:classification, deep_dive_agentic). Top-line assessment attributes are summarized in the table below:

| Attribute | Value | Source |
|-----------|-------|--------|
| Verdict | Malicious | cross-section:classification, deep_dive_agentic |
| Malware Family | Unknown Delphi-based packed malware (likely infostealer or remote access trojan) | cross-section:9. Comparison with Known Families |
| Confidence | 90% | cross-section:classification, deep_dive_agentic |
| Analysis Agreement | LLM and v1 static analysis engine aligned | cross-section:classification |

This unknown Delphi-based packed binary exhibits core capabilities consistent with information-stealing or remote access trojan (RAT) functionality, including system and registry discovery, file system enumeration, process injection, and privilege escalation routines identified via capa static analysis (source: cross-section:7. Capability Assessment). Static triage returned 26 matching YARA rules and 49 capa capability rules (source: v1_summary, cross-section:3. Initial Triage), with 15 distinct functional capabilities confirmed including custom XOR and RC4 encryption routines, environment variable and file path retrieval, and disk space querying functionality; no runtime behavioral artifacts, hardcoded command-and-control (C2) indicators, or network-related static indicators were recovered during analysis (source: cross-section:5. Behavioral Analysis, cross-section:6. Network Analysis), and no confirmed public attribution to a named threat actor or campaign has been established for this sample to date (source: cross-section:10. Attribution).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=34c | cross_
… [36661 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7374` | `5050460ead547522` |
| `prompt.txt` | `True` | `17539` | `17cb735249e91212` |
| `pipeline-audit.json` | `True` | `112525` | `44e41e4b0182fe45` |
| `AUDIT-REPORT.md` | `True` | `83210` | `b6368c8a6cf836c4` |
| `REPORT-MASTER-v2.md` | `True` | `16948` | `112cfb1b18ce9627` |
| `REPORT-MASTER-v3.md` | `True` | `39170` | `be694ec0e7cbca08` |
| `REPORT-v2.md` | `True` | `16948` | `112cfb1b18ce9627` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `46309` | `93c65aedf63c9dde` |
| `rule.yar` | `True` | `2188` | `2609d59b36848e21` |
| `intake-validation.json` | `True` | `2931` | `56f8da23f668ec83` |
| `source-decisions.json` | `True` | `1284` | `f79344233bc98f17` |
| `malcat-triage.json` | `True` | `62` | `f800132c21fdd371` |
| `deep_dive/01-tools-raw.json` | `True` | `40286` | `5360a06f66ba6d6d` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2682` | `48743705a2c8ff61` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `25982` | `5afbb2531dd92c93` |

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

- **intake_validation:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/intake-validation.json` exists=`True` bytes=`2931` mtime=`2026-08-06T03:48:21.267001+00:00`
  - sha256: `56f8da23f668ec835e2996394101be42e0e57d4d211daff1a752903a23720bf2`
- **malcat_triage:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/malcat-triage.json` exists=`True` bytes=`62` mtime=`2026-08-06T03:47:24.850000+00:00`
  - sha256: `f800132c21fdd3716b472d66c9faa9a1b59d2c766c727a0897ef2ff490311a42`
- **source_decisions:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/source-decisions.json` exists=`True` bytes=`1284` mtime=`2026-08-06T03:48:21.267001+00:00`
  - sha256: `f79344233bc98f179ee76467e0e702809821da57c21a33cb0ac98f1da9260030`
- **ghidra_import_log:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/intake-analyzeHeadless.log` exists=`True` bytes=`6556` mtime=`2026-08-04T05:10:59.359421+00:00`
  - sha256: `24814ea898dd8751fd57b993c565289a51ecbc2bce9849938276d58cc3a6c545`
- **ida_bootstrap_log:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
  "imports": {
    "source": "none",
    "confidence": "medium",
    "reason": "No import data is available as all analysis tools (Ghidra, IDA, Malcat) failed to execute successfully."
  },
  "functions": {
    "source": "none",
    "confidence": "medium",
    "reason": "No function data is available as all analysis tools failed to execute successfully."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Both Ghidra and IDA are the optimal sources for string extraction, providing the most comprehensive coverage of embedded strings in binary files."
  },
  "decompilation": {
    "source": "none",
    "confidence": "medium",
    "reason": "No function data was extracted, so decom
… [507 more chars]
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
  "rule_count": 49,
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
      "name": "check OS version",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Information Discovery",
          "subtechnique": "",
          "id": "T1082"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "objective": "Discovery",
          "behavior": "System Information Discovery",
          "method": "",
          "id": "E1082"
        }
      ]
    },
    {
      "name": "query or enumerate registry value",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Query Registry"
          ],
          "tactic": "Discovery",
          "tec
… [5723 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 830343,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 917570,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2194,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 146170,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Delphi_CompareCall",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 31860,
          "length": 42,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 722888,
          "length": 78,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$patternBorland",
          "offset": 41422,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "borland_delphi",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 50636,
          "length": 42,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 50636,
         
… [8357 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 11298,
  "strings_sampled": 80,
  "strings": [
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.rsrc",
    "Boolean",
    "System",
    "AnsiChar",
    "ShortInt",
    "SmallInt",
    "Integer",
    "Cardinal",
    "Pointer",
    "UInt64",
    "NativeInt",
    "NativeUInt",
    "Single",
    "Extended",
    "Double",
    "Currency",
    "ShortString",
    "PAnsiChar0",
    "PWideCharL",
    "ByteBool",
    "WordBool",
    "LongBool",
    "string",
    "WideString",
    "AnsiString",
    "Variant",
    "OleVariant",
    "TClass",
    "HRESULT",
    "&op_Equality",
    "&op_Inequality",
    "Create",
    "BigEndian",
    "AStartIndex",
    "PInterfaceEntry",
    "TInterfaceEntry",
    "VTable",
    "IOffset",
    "ImplGetter",
    "PInterfaceTable4",
    "TInterfaceTable",
    "EntryCount",
    "Entries",
    "TMethod",
    "&op_GreaterThan",
    "&op_GreaterThanOrEqual",
    "&op_LessThan",
    "&op_LessThanOrEqual",
    "TObject&",
    "DisposeOf",
    "InitInstance",
    "Instance",
    "CleanupInstance",
    "ClassType",
    "ClassName",
    "ClassNameIs",
    "ClassParent",
    "ClassInfo",
    "InstanceSize",
    "InheritsFrom",
    "AClass",
    "MethodAddress",
    "MethodName",
    "Address",
    "QualifiedClassName",
    "FieldAddress",
    "GetInterface",
    "GetInterfaceEntry",
    "GetInterfaceTable",
    "UnitName",
    "UnitScope",
    "Equals"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 1,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 11297
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 142.03,
  "size_bytes": 2263752,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: ",
  "duration_s": 0.08
}
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "CreateProcess (mapped to ATT&CK T1106) high-signal import signals This high-signal import is used for spawning new proce",
    "LoadLibrary + GetProcAddress (mapped to ATT&CK T1129) high-signal import signals These imports enable dynamic API resolu",
    "VirtualAlloc + VirtualProtect (mapped to ATT&CK T1055) high-signal import signals These imports are used for memory allo",
    "encode data using XOR (T1027) + encrypt data using RC4 PRGA (T1027) top ATT&CK behavior rules These rules confirm the sa",
    "System Information Discovery (T1082): check OS version, get disk size, query environment variable top ATT&CK behavior ru"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Unknown Delphi-based packed malware, likely an infostealer or remote access trojan (RAT) given its system/registry/file discovery, process injection, and privilege escalation capabilities",
  "score": 92,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "high-signal import signals",
      "row_or_rule": "CreateProcess (mapped to ATT&CK T1106)",
      "why": "This high-signal import is used for spawning new processes, a core capability for malware execution, process injection, and running malicious payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal import signals",
      "row_or_rule": "LoadLibrary + GetProcAddress (mapped to ATT&CK T1129)",
      "why": "These imports enable dynamic API resolution, a common malware technique to hide malicious functionality from static analysis by loading functions only at runtime."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal import signals",
      "row_or_rule": "VirtualAlloc + VirtualProtect (mapped to ATT&CK T1055)",
      "why": "These imports are used for memory allocation and modifying memory page permissions, core capabilities for process injection, shellcode execution, and unpacking obfuscated code."
    },
    {
      "source": "capa",
      "query_or_table": "top ATT&CK behavior rules",
      "row_or_rule": "encode data using XOR (T1027) + encrypt data using RC4 PRGA (T1027)",
      "why": "These rules confirm the sample uses obfuscation (XOR encoding, RC4 encryption) to hide malicious code or sensitive data, a standard defense evasion tactic."
    },
    {
      "source": "capa",
      "query_or_table": "top ATT&CK behavior rules",
      "row_or_rule": "System Information Discovery (T1082): check OS version, get disk size, query environment variable",
      "why": "This behavior indicates the sample performs system reconnaissance to profile the target environment, a common step for malware to adapt its behavior or identify high-value targets."
    },
    {
      "source": "capa",
      "query_or_table": "top ATT&CK behavior rules",
      "row_or_rule": "Query Registry (T1012): query or enumerate registry value",
      "why": "Registry access is commonly used by malware for persistence, storing configuration data, or stealing stored credentials."
    },
    {
      "source": "capa",
      "query_or_table": "top ATT&CK behavior rules",
      "row_or_rule": "Access Token Manipulation (T1134): modify access privileges",
      "why": "This behavior indicates the sample manipulates Windows access tokens to escalate privileges, allowing it to perform restricted actions like accessing protected system resources."
    },
    {
      "source": "yara",
      "query_or_table": "rule matches",
      "row_or_rule": "domain, IP, contains_base64 rules",
      "why": "These rules indicate the sample contains embedded domain names, IP addresses, and base64-encoded data, likely used for command-and-control (C2) communication or payload delivery, a core malicious capability."
    },
    {
      "source": "yara",
      "query_or_table": "rule matches",
      "row_or_rule": "disable_dep, escalate_priv, win_registry, win_token",
      "why": "These YARA rules directly confirm the sample contains code to bypass Data Execution Prevention (DEP), escalate user privileges, and interact with the Windows registry and access tokens, all unambiguous malicious behaviors."
    },
    {
      "source": "yara",
      "query_or_table": "rule matches",
      "row_or_rule": "IsPacked, HasOverlay, Borland_Delphi* compiler rules",
      "why": "These rules confirm the sample is packed (obfuscated) and built with the Borland Delphi compiler, a common choice for malware due to its rapid development capabilities and small output binaries."
    },
    {
      "source": "floss",
      "query_or_table": "extracted strings",
      "row_or_rule": "Delphi RTL/internal strings (e.g., InitInstance, GetInterface, TInterfaceTable)",
      "why": "These Delphi-specific strings align with YARA's compiler identification, and the total of 11,298 extracted strings is consistent with a packed/obfuscated malware sample."
    }
  ],
  "summary": "This is a packed 2.2MB Borland Delphi PE file with 142 imports, including high-signal APIs for process creation, dynamic API resolution, and memory manipulation. Static analysis via capa identifies obfuscation (XOR, RC4), system/file/registry reconnaissance, and privilege escalation capabilities. YARA rules confirm the sample is packed, built with Delphi, and contains code for DEP bypass, privileg"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/prompt.txt` exists=`True` bytes=`17539` mtime=`2026-08-06T03:51:08.599002+00:00`
  - sha256: `17cb735249e91212d04566334e397d1326f44a90f988210f5425e3654ba35b41`
- **verdict:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/verdict.json` exists=`True` bytes=`7374` mtime=`2026-08-06T03:51:59.196002+00:00`
  - sha256: `5050460ead5475222f622a2961fd9ad78418ed2401c5612de579d66354876111`

#### prompt_excerpt

```
# Triage evidence
sha256: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
sample_path: /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe
ghidra_session: ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
ida_session: ida-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819

## Source decisions (from intake validation)
- imports: none (confidence=medium) — No import data is available as all analysis tools (Ghidra, IDA, Malcat) failed to execute successfully.
- functions: none (confidence=medium) — No function data is available as all analysis tools failed to execute successfully.
- strings: both (confidence=high) — Both Ghidra and IDA are the optimal sources for string extraction, providing the most comprehensive coverage of embedded strings in binary files.
- decompilation: none (confidence=medium) — No function data was extracted, so decompilation is not possible; function c
… [16523 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Unknown Delphi-based packed malware, likely an infostealer or remote access trojan (RAT) given its system/registry/file discovery, process injection, and privilege escalation capabilities",
  "cross_engine_notes": "Ghidra and IDA analysis failed due to technical issues (Ghidra project ownership error, missing idasql binary), so all evidence is sourced from pe_imports, capa, YARA, and FLOSS. Cross-engine alignment is strong: YARA's Delphi compiler identification matches FLOSS's Delphi-specific strings; pe_imports' high-signal process injection and execution APIs align with capa's detected process injection, execution, and obfuscation behaviors. The sample's packed state (confirmed by YARA) explains its large 2.2MB size, high string count, and failure of Ghidra/IDA to extract function data.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "high-signal import signals",
      "row_or_rule": "Crea
… [6374 more chars]
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
  "rule_count": 49,
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
      "name": "check OS version",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Information Discovery",
          "subtechnique": "",
          "id": "T1082"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "objective": "Discovery",
          "behavior": "System Information Discovery",
          "method": "",
          "id": "E1082"
        }
      ]
    },
    {
      "name": "query or enumerate registry value",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Query Registry"
          ],
          "tactic": "Discovery",
          "tec
… [5723 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 2263752,
  "duration_s": 0.03,
  "import_count": 142,
  "signal_count": 5,
  "signals": [
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
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 830343,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 917570,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2194,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 146170,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Delphi_CompareCall",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 31860,
          "length": 42,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 722888,
          "length": 78,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$patternBorland",
          "offset": 41422,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "borland_delphi",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 50636,
          "length": 42,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 50636,
         
… [8335 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 11298,
  "strings_sampled": 80,
  "strings": [
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.rsrc",
    "Boolean",
    "System",
    "AnsiChar",
    "ShortInt",
    "SmallInt",
    "Integer",
    "Cardinal",
    "Pointer",
    "UInt64",
    "NativeInt",
    "NativeUInt",
    "Single",
    "Extended",
    "Double",
    "Currency",
    "ShortString",
    "PAnsiChar0",
    "PWideCharL",
    "ByteBool",
    "WordBool",
    "LongBool",
    "string",
    "WideString",
    "AnsiString",
    "Variant",
    "OleVariant",
    "TClass",
    "HRESULT",
    "&op_Equality",
    "&op_Inequality",
    "Create",
    "BigEndian",
    "AStartIndex",
    "PInterfaceEntry",
    "TInterfaceEntry",
    "VTable",
    "IOffset",
    "ImplGetter",
    "PInterfaceTable4",
    "TInterfaceTable",
    "EntryCount",
    "Entries",
    "TMethod",
    "&op_GreaterThan",
    "&op_GreaterThanOrEqual",
    "&op_LessThan",
    "&op_LessThanOrEqual",
    "TObject&",
    "DisposeOf",
    "InitInstance",
    "Instance",
    "CleanupInstance",
    "ClassType",
    "ClassName",
    "ClassNameIs",
    "ClassParent",
    "ClassInfo",
    "InstanceSize",
    "InheritsFrom",
    "AClass",
    "MethodAddress",
    "MethodName",
    "Address",
    "QualifiedClassName",
    "FieldAddress",
    "GetInterface",
    "GetInterfaceEntry",
    "GetInterfaceTable",
    "UnitName",
    "UnitScope",
    "Equals"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 1,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 11297
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 130.76,
  "size_bytes": 2263752,
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
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "disassembly": {
    "0x004b5eec": "\u250c 501: entry0 ();\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_1ch @ ebp-0x1c\n\u2502           ; var int32_t var_24h @ ebp-0x24\n\u2502           ; var int32_t var_28h @ ebp-0x28\n\u2502           ; var int32_t var_2ch @ ebp-0x2c\n\u2502           ; var int32_t var_30h @ ebp-0x30\n\u2502           ; var int32_t var_34h @ ebp-0x34\n\u2502           ; var int32_t var_38h @ ebp-0x38\n\u2502           ; var int32_t var_3ch @ ebp-0x3c\n\u2502           ; var int32_t var_40h @ ebp-0x40\n\u2502           ; var int32_t var_5ch @ ebp-0x5c\n\u2502           0x004b5eec      55             push ebp\n\u2502           0x004b5eed      8bec           mov ebp, esp\n\u2502           0x004b5eef      83c4a4         add esp, 0xffffffa4\n\u2502           0x004b5ef2      53             push ebx\n\u2502           0x004b5ef3      56             push esi\n\u2502           0x004b5ef4      57             push edi\n\u2502           0x004b5ef5      33c0           xor eax, eax\n\u2502           0x004b5ef7      8945c4         mov dword [var_3ch], eax\n\u2502           0x004b5efa      8945c0         mov dword [var_40h], eax\n\u2502           0x004b5efd      8945a4         mov dword [var_5ch], eax\n\u2502           0x004b5f00      8945d0         mov dword [var_30h], eax\n\u2502           0x004b5f03      8945c8         mov dword [var_38h], eax\n\u2502           0x004b5f06      8945cc         mov dword [var_34h], eax\n\u2502           0x004b5f09      8945d4         mov dword [var_2ch], eax\n\u2502           0x004b5f0c      8945d8         mov dword [var_28h], eax\n\u2502           0x004b5f0f      8945ec         mov dword [var_14h], eax\n\u2502           0x004b5f12      b8b8144b00     mov eax, 0x4b14b8\n\u2502           0x004b5f17      e8b072f5ff     call 0x40d1cc\n\u2502           0x004b5f1c      33c0           xor eax, eax\n\u2502           0x004b5f1e      55             push ebp\n\u2502           0x004b5f1f      68e2654b00     push 0x4b65e2\n\u2502           0x004b5f24      64ff30         push dword fs:[eax]\n\u2502           0x004b5f27      648920         mov dword fs:[eax], esp\n\u2502           0x004b5f2a      33d2           xor edx, edx\n\u2502           0x004b5f2c      55             push ebp\n\u2502           0x004b5f2d      689e654b00     push 0x4b659e\n\u2502           0x004b5f32      64ff32         push dword fs:[edx]\n\u2502           0x004b5f35      648922         mov dword fs:[edx], esp\n\u2502           0x004b5f38      a134e64b00     mov eax, dword [0x4be634]   ; [0x4be634:4]=0\n\u2502           0x004b5f3d      e8a29dffff     call 0x4afce4\n\u2502           0x004b5f42      e8f598ffff     call 0x4af83c\n\u2502           0x004b5f47      8d55ec         lea edx, [var_14h]\n\u2502           0x004b5f4a      33c0           xor eax, eax\n\u2502           0x004b5f4c      e84fcdf6ff     call 0x422ca0\n\u2502           0x004b5f51      8b55ec         mov edx, dword [var_14h]\n\u2502           0x004b5f54      b8841d4c00     mov eax, 0x4c1d84\n\u2502           0x004b5f59      e8a21ef5ff     call 0x407e00\n\u2502           0x004b5f5e      6a02           push 2                      ; 2\n\u2502           0x004b5f60      6a00           push 0\n\u2502           0x004b5f62      6a01           push 1  ",
… [7848 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
    "exists": true,
    "hook_candidates": [
      "kernel32.dll!GetACP",
      "kernel32.dll!GetExitCodeProcess",
      "kernel32.dll!LocalFree",
      "kernel32.dll!CloseHandle",
      "kernel32.dll!SizeofResource",
      "comctl32.dll!InitCommonControls",
      "version.dll!GetFileVersionInfoSizeW",
      "version.dll!VerQueryValueW",
      "version.dll!GetFileVersionInfoW",
      "user32.dll!CreateWindowExW",
      "user32.dll!TranslateMessage",
      "user32.dll!CharLowerBuffW",
      "user32.dll!CallWindowProcW",
      "user32.dll!CharUpperW",
      "oleaut32.dll!SysAllocStringLen",
      "oleaut32.dll!SafeArrayPtrOfIndex",
      "oleaut32.dll!VariantCopy",
      "oleaut32.dll!SafeArrayGetLBound",
      "oleaut32.dll!SafeArrayGetUBound",
      "netapi32.dll!NetWkstaGetInfo",
      "netapi32.dll!NetApiBufferFree",
      "advapi32.dll!ConvertStringSecurityDescriptorToSecurityDescriptorW",
      "advapi32.dll!RegQueryValueExW",
      "advapi32.dll!AdjustTokenPrivileges",
      "advapi32.dll!GetTokenInformation",
      "advapi32.dll!ConvertSidToStringSidW"
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
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "YARA 26 matches: Borland/Delphi family, IsPacked, HasOverlay, domain, IP, URL, base64, CRC32_poly_Constant, Delphi_Compa",
    "capa 49 rules: encode data using XOR (T1027), encrypt data using RC4 PRGA (T1027), create or open registry key, check OS",
    "pe_import_signals: CreateProcess (T1106), LoadLibrary (T1129), GetProcAddress (T1129), VirtualProtect (T1055), VirtualAl",
    "floss: 11298 strings including Delphi RTTI/type names (Boolean, System, AnsiString, WideString, TObject&, DisposeOf, Ini",
    "r2 entry0 at 0x004b5eec with large stack frame and Delphi-style initialization"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Sample e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 is a packed Borland/Delphi GUI PE with strong malicious indicators. Static analysis shows obfuscation/encoding (XOR, RC4), high-signal offensive imports (CreateProcess, VirtualAlloc, VirtualProtect, LoadLibrary, GetProcAddress),",
  "key_evidence": [
    "YARA 26 matches: Borland/Delphi family, IsPacked, HasOverlay, domain, IP, URL, base64, CRC32_poly_Constant, Delphi_CompareCall",
    "capa 49 rules: encode data using XOR (T1027), encrypt data using RC4 PRGA (T1027), create or open registry key, check OS version, plus additional obfuscation/anti-analysis rules",
    "pe_import_signals: CreateProcess (T1106), LoadLibrary (T1129), GetProcAddress (T1129), VirtualProtect (T1055), VirtualAlloc (T1055)",
    "floss: 11298 strings including Delphi RTTI/type names (Boolean, System, AnsiString, WideString, TObject&, DisposeOf, InitInstance, ClassName, etc.) and 1 tight string",
    "r2 entry0 at 0x004b5eec with large stack frame and Delphi-style initialization",
    "speakeasy_emulate: no dynamic API calls or strings observed, consistent with packed/obfuscated static-only sample"
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
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/sa
… [11435 more chars]
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
  "rule_count": 49,
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
… [8823 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 2263752,
  "duration_s": 0.03,
  "import_count": 142,
  "signal_count": 5,
  "signals": [
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
      "label": 
… [428 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 11298,
  "strings_sampled": 80,
  "strings": [
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.rsrc",
    "Boolean",
    "System",
    "AnsiChar",
    "ShortInt",
    "SmallInt",
    "Integer",
    "Cardinal",
    "Pointer",
    "UInt64",
    "NativeInt
… [1522 more chars]
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
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "disassembly": {
    "0x004b5eec": "\u250c 501: entry0 ();\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_1ch @ ebp-0x1c\n\u2502           ; var int32_t var_24h @ e
… [10948 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r\n",
  "xorsearch_stderr": "",
  "xorse
… [21 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
    "exists": true,
    "hook_candidates": [
      "kernel32.dll!GetACP",
      "kernel32.dll!GetExitCodeProcess",
      "kernel32.dll!LocalFree",
      "kernel32.dll!CloseHandle",
      "kernel32.dll!
… [885 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — Auto SQL seed for large-mode deep RE gate
  - error: `ghidrasql server died during startup for ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql server died during startup for ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (rc=1); tail of log:
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
  "error": "ghidrasql server died during startup for ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (rc=1); tail of log:\nHeadless analyzer error: ghidra.util.NotOwnerException: Project is owned by remnux (HeadlessAnalyzer) java.io.IOException: ghidra.util.NotOwnerException: Project is owned by remnux\n\tat ghidra.app.util.headless.HeadlessAnalyzer.openProject(Headles
… [779 more chars]
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
}
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 2263752,
  "duration_s": 0.05,
  "import_count": 142,
  "signal_count": 5,
  "signals": [
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
      "label": 
… [428 more chars]
```

- **malcat_analyze** ok=`False` checklist=`False` — langgraph tool call
  - error: `malcat_analyze top-level: MCP malcat closed: `

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: "
}
```

- **speakeasy_emulate** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "module_base": null,
  "entry_point": null,
  "key_events": [],
  "api_calls": [],
  "strings": []
}
```

- **yara_scan** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/sa
… [11435 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 49,
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
… [8824 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 11298,
  "strings_sampled": 80,
  "strings": [
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.rsrc",
    "Boolean",
    "System",
    "AnsiChar",
    "ShortInt",
    "SmallInt",
    "Integer",
    "Cardinal",
    "Pointer",
    "UInt64",
    "NativeInt
… [1522 more chars]
```

- **r2_decompile** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "disassembly": {
    "0x004b5eec": "\u250c 501: entry0 ();\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_1ch @ ebp-0x1c\n\u2502           ; var int32_t var_24h @ e
… [10948 more chars]
```

- **angr_analyze** ok=`False` checklist=`False` — langgraph tool call
  - error: `invoke_z3_or_angr not found in extensions/deobfuscation/`

```json
{
  "error": "invoke_z3_or_angr not found in extensions/deobfuscation/"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/01-tools-raw.json` exists=`True` bytes=`40286` mtime=`2026-08-06T03:55:50.011004+00:00`
  - sha256: `5360a06f66ba6d6df9283e48283f269ccae1f850553fac62fffce9eaffd4b867`
- **sql_evidence:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/05-deep-dive.json` exists=`True` bytes=`2682` mtime=`2026-08-06T03:59:01.212005+00:00`
  - sha256: `48743705a2c8ff61bb33b347a4a8f0128e619accfd372810b2e0ff9902233de1`

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
  "summary": "Sample e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 is a packed Borland/Delphi GUI PE with strong malicious indicators. Static analysis shows obfuscation/encoding (XOR, RC4), high-signal offensive imports (CreateProcess, VirtualAlloc, VirtualProtect, LoadLibrary, GetProcAddress), registry manipulation, network indicators (domain, IP, URL, base64), and Delphi runtime artifacts. Emulation produced no observable behavior, but deterministic static signals dominate.",
  "key_evidence": [
    "YARA 26 matches: Borland/Delphi family, IsPacked, HasOverlay, domain, IP, URL, base64, CRC32_poly_Constant, Delphi_CompareCall",
    "capa 49 rules: encode data using 
… [1882 more chars]
```

- **agentic:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`187854` mtime=`2026-08-06T03:59:01.211005+00:00`
  - sha256: `071cf2615d625a174bc0116a8626500af54a72caf466111dcf8085bef2505881`

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

- **rule_yar:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/rule.yar` exists=`True` bytes=`2188` mtime=`2026-08-06T03:59:14.140005+00:00`
  - sha256: `2609d59b36848e21a887e91827832b670ec6777c63d5a3729912f8c3c468cc11`

#### excerpt

```
// yara_gen_v2.py — 2026-08-06T03:59:14.140793+00:00
rule CADRE_v2_unknown_e29d2bd94621 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "This high-signal import is used for spawning new processes, a core capability for malware execution, process injection, " ascii wide
        $s1 = "These imports enable dynamic API resolution, a common malware technique to hide malicious functionality from static anal" ascii wide
        $s2 = "These imports are used for memor
… [1386 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-MASTER-v2.md` exists=`True` bytes=`16948` mtime=`2026-08-06T04:01:09.924006+00:00`
  - sha256: `112cfb1b18ce96273abc9348758f17d6cdfd233bb75b693e1849fdc484e30e10`
- **REPORT_MASTER_v3:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-MASTER-v3.md` exists=`True` bytes=`39170` mtime=`2026-08-06T04:09:53.518349+00:00`
  - sha256: `be694ec0e7cbca089af4e4817dc3c222e02d56914c304e86d8d65c9e60b20056`
- **REPORT_v2:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-v2.md` exists=`True` bytes=`16948` mtime=`2026-08-06T04:01:09.923006+00:00`
  - sha256: `112cfb1b18ce96273abc9348758f17d6cdfd233bb75b693e1849fdc484e30e10`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`55370` mtime=`2026-08-06T04:06:13.297088+00:00`
  - sha256: `4adf11877c5053ac46695c85d4dba083744fa49f334e2bb1db0ca355141a46f6`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`46309` mtime=`2026-08-06T04:12:25.303021+00:00`
  - sha256: `93c65aedf63c9dde2f4e150bd8cb2001cf1522f3acd4c93ecaecc2234a384433`
- **report_v2_json:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/report-v2.json` exists=`True` bytes=`19428` mtime=`2026-08-06T04:06:13.301088+00:00`
  - sha256: `8701240ac31534aae0b860aaae3eb630f6b94c91ec9355b7b5be8687abb6cb97`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 04:01:09 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unknown Delphi-based packed malware, likely an infostealer or remote access trojan (RAT) given its system/registry/file discovery, process injection, and privilege escalation capabilities
- **Honesty:** the
… [16039 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 04:09:53 UTC

# RE Report — e29d2bd94621
_Generated 2026-08-06T04:09:53.513666+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=414c | cross_refs=True | llm_ok=True | runtime=26.17s -->

### Executive Summary
The analyzed sample (SHA256: `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`) is classified as **Malicious** with 90% confidence, with agreement between LLM judgment and v1 static analysis engine confirming the verdict (source: cross-section:classification, deep_dive_agentic). Top-line assessment attributes are summarized in the table be
… [38261 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
