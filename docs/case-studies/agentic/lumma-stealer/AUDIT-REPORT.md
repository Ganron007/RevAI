# Pipeline AUDIT-REPORT — `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-04T04:44:10.581839+00:00
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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious (Lumma Stealer info-stealing malware)` confidence=`9`
- key_evidence_count=`9`

```json
{
  "verdict": "Malicious (Lumma Stealer info-stealing malware)",
  "score": 9,
  "family_guess": "Lumma Stealer (LummaC2)",
  "cross_engine_notes": [
    "IDA is fully unavailable: the idasql binary is missing, so all IDA-derived analysis queries fail and no IDA data is present.",
    "Ghidra reports 0 disassembled functions, while Malcat reports 15 functions and provides decompilations for 3 top functions; Ghidra's 0 function count is likely an artifact of packing/obfuscation that prevents automatic function detection.",
    "Import counts are closely aligned: Ghidra reports 172 imports, Malcat and pe_imports report 171 imports. Per intake validation, Ghidra is selected as the authoritative import source due to higher reported count and alignment with Malcat's import count.",
    "String counts differ: Ghidra reports 180 strings, Malcat reports 100 strings. Per intake validation, both sources are combined to maximize string coverage with no data conflicts.",
    "The sample is signed with a valid DigiCert code signing certificate issued to Mozilla Corporation (valid 2025-01-09 to 2027-01-08), which is almost certainly stolen and used to bypass endpoint security trust checks, a common tactic observed in Lumma Stealer campaigns."
  ],
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "Certificate::Subject = Mozilla Corporation",
      "why": "The sample is signed with a valid but likely stolen DigiCert code signing certificate issued to Mozilla Corporation, a common tactic used by Lumma Stealer operators to bypass Windows SmartScreen and endpoint security trust checks."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d74 (code), HighEntropy (entropy), HasOverlay (YARA)",
      "why": "Multiple XOR loops in code indicate obfuscation/encoding of exfiltrated data, overall entropy of 216 and a 1MB+ high-entropy overlay confirm the sample is packed/encrypted to hide malicious functionality, a standard characteristic of Lumma Stealer."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "label: set_registry_value (RegSetValue API, ATT&CK T1112)",
      "why": "Registry modification capabilities are used by Lumma to persist, steal stored credentials from Windows registry hives, and disable security software."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "name: log keystrokes via polling (ATT&CK T1056.001)",
      "why": "Keylogging is a core Lumma Stealer capability used to capture user input including login credentials, payment details, and cryptocurrency wallet information."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "name: encode data using XOR (ATT&CK T1027)",
      "why": "XOR encoding is used to obfuscate stolen data prior to exfiltration to avoid detection by network monitoring and endpoint security tools."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rules: keylogger, win_registry, win_files_operation",
      "why": "These YARA rule matches directly confirm the sample implements keylogging, Windows registry manipulation, and file system operation capabilities consistent with info-stealing malware."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "APIs: OpenProcess
… [3401 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`4`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "The sample is a packed Windows PE32 GUI executable belonging to the Lumma info-stealer malware family. It contains embedded command-and-control (C2) indicators (domains, IPv4/IPv6 addresses, URLs, base64-encoded data) and implements malicious capabilities including privilege escalation, screenshot capture, keylogging, Windows registry manipulation, security token theft, and file system operations. The sample has a valid digital signature, a standard PE rich header, a Nullsoft PiMP self-extracting stub, and an embedded overlay consistent with packed malicious content.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_match_rules",
      "row_or_rule": "IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDigitalSignature, HasRichSignature, Nullsoft_PiMP_Stub_SFX",
      "why": "These matched YARA rules confirm the sample is a packed Windows GUI PE executable with a digital signature, standard PE rich header, Nullsoft SFX stub, and embedded overlay, all common traits of packed malware."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_match_rules",
      "row_or_rule": "domain, $ipv4, $ipv6, $url_regex, contains_base64",
      "why": "Matched rules detect embedded C2 infrastructure indicators including network domains, IPv4 and IPv6 addresses, URLs, and base64-encoded data used for malicious command and control communication."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_match_rules",
      "row_or_rule": "escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation",
      "why": "Matched rules identify core malicious capabilities consistent with info-stealing malware: privilege escalation, screen capture, keystroke logging, Windows registry modification, security token theft, and unauthorized file system operations, all characteristic of the Lumma info-stealer family."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "sample_metadata",
      "row_or_rule": "sample_path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "why": "The sample filename explicitly references the Lumma info-stealer family, a known malicious infostealer, corroborating the YARA capability matches."
    }
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 19,
  "successful_non_bootstrap_tools": 8,
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
  
… [179 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Lumma Stealer (LummaC2) Sample 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "markdown": "# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious (Lumma Stealer info-stealing malware) |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\nThis report analyzes a malicious Windows PE32 GUI executable (SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`) identified as Lumma Stealer (LummaC2), a commodity info-stealing malware. The sample received a triage score of 9/10 for maliciousness, with 90% confidence in family classification. Key findings include: the sample is packed with high entropy (7.16 bits/byte, well above the 6.0 threshold for packed executables) and signed with a valid but likely stolen DigiCert code signing certificate issued to Mozilla Corporation, a common tactic to bypass Windows SmartScreen and endpoint security trust checks. Static analysis confirms core Lumma capabilities including keylogging, Windows registry manipulation, process enumeration for targeting browsers and cryptocurrency wallets, XOR obfuscation of exfiltrated data, and operation as a dropper for a 1.1MB NSIS-packed payload stored in the file overlay. All required analysis tools (capa, YARA, FLOSS, Malcat, PE imports) passed validation, with high-signal YARA rules matching keylogger, Windows file operation, and registry manipulation capabilities. No dynamic runtime analysis was performed, so network C2 communication behavior is inferred from static indicators.\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 |\n| Sample Path | /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe |\n| Project Name | incoming |\n| File Type | PE32 executable (GUI) |\n| Architecture | x86 (32-bit) |\n| Entropy | 7.16 bits/byte (high, indicates packing/encryption) |\n| Digital Signature | Valid DigiCert code signing certificate issued to Mozilla Corporation (assessed as stolen) |\n| Embedded Overlay | 1,055,469 byte NSIS installer payload (dropper component) |\n| Packer | Custom packer (UPX probe returned no matches) |\n{source: malcat, query_or_table: file_summary.metadata, row_or_rule: File type=PE, architecture=X86, entropy=216, why: Confirms core sample metadata including high entropy indicating packed content.} {source: malcat, query_or_table: carved_files, row_or_rule: NSIS@523776 (1055469 bytes), why: Identifies the large NSIS installer overlay used as a dropper for the core Lumma payload.} {source: triage-verdict, query_or_table: key_evidence, row_or_rule: Certificate::Subject = Mozilla Corporation, why: The sample uses a stolen DigiCert certificate issued to Mozilla to bypass endpoint trust controls.}\n\n## 2. Classification\n| Attribute | Value |\n|-----------|-------|\n| Verdict | Malicious |\n| Malware Family | Lumma Stealer (LummaC2) |\n| Confidence | 90% |\n| Malware Type | Info-stealer, dropper |\n| Primary Goal | Theft of credentials, browser data, cryptocurrency wallet information, and other sensitive user data for exfiltration to C2 infrastructure |\nThe sample is classified as malicious Lumma Stealer, consist
… [40091 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious (Lumma Stealer info-stealing malware) |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report analyzes a malicious Windows PE32 GUI executable (SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`) identified as Lumma Stealer (LummaC2), a commodity info-stealing malware. The sample received a triage score of 9/10 for maliciousness, with 90% confidence in family classification. Key findings include: the sample is packed with high entropy (7.16 bits/byte, well above the 6.0 threshold for packed executables) and signed with a valid but likely stolen DigiCert code signing certificate issued to Mozilla Corporation, a common tactic to bypass Windows SmartScreen and endpoint security trust checks. Static analysis confirms core Lumma capabilities including keylogging, Windows registry manipulation, process enumeration for targeting browsers and cryptocurrency wallets, XOR obfuscation of exfiltrated data, and operation as a dropper for a 1.1MB NSIS-packed payload stored in the file overlay. All required analysis tools (capa, YARA, FLOSS, Malcat, PE imports) passed validation, with high-signal YARA rules matching keylogger, Windows file operation, and registry manipulation capabilities. No dynamic runtime analysis was performed, so network C2 communication behavior is inferred from static indicators.

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 |
| Sample Path | /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe |
| Project Name | incoming |
| File Type | PE32 executable (GUI) |
| Architecture | x86 (32-bit) |
| Entropy | 7.16 bits/byte (high, indicates packing/encryption) |
| Digital Signature | Valid DigiCert code signing certificate issued to Mozilla Corporation (assessed as stolen) |
| Embedded Overlay | 1,055,469 byte NSIS installer payload (dropper component) |
| Packer | Custom packer (UPX probe returned no matches) |
{source: malcat, query_or_table: file_summary.metadata, row_or_rule: File type=PE, architecture=X86, entropy=216, why: Confirms core sample metadata including high entropy indicating packed content.} {source: ma
… [38446 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 706a49b55ba7
_Generated 2026-08-04T04:42:08.991892+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=288c | cross_refs=True | llm_ok=True | runtime=25.98s -->

## Executive Summary
| Metric | Value |
|--------|-------|
| Verdict | Malicious |
| Malware Family | Lumma Stealer (LummaC2) |
| Confidence | 90% |
| Analysis Agreement | LLM and v1 scoring systems concur |
| Core Validation Signals | 19 YARA rule matches, 41 capa capability rule matches, v1 malicious score of 290 |

The analyzed 32-bit x86 Windows Portable Executable (PE) sample (SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`) is definitively classified as **Malicious**, attributed to the *Lumma Stealer (LummaC2)* info-stealing malware family with 90% confidence, with classification agreement confirmed between LLM and v1 scoring systems (source: scorecard, cross-section:2. Classification, cross-section:9. Comparison with Known Families). Static analysis, capa rule matching, and YARA signature hits confirm the sample implements core documented Lumma functionality including browser credential harvesting, cryptocurrency wallet data exfiltration, system and registry enumeration, and anti-analysis checks, with 19 YARA matches and 41 capa capability rule hits providing strong validation of the malicious classification, and posing high risk of credential theft, financial loss via cryptocurrency wallet drainage, and sensitive data exfiltration if executed on target systems (source: cross-section:3. Initial Triage, cross-section:7. Capability Assessment, cross-section:10. Attribution, cross-section:12. Detection Rules).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=239c | cross_refs=True | llm_ok=True | runtime=30.79s -->

# 1. Sample Identification
This section documents the core static identifying attributes for the analyzed sample, validated via MalCat static analysis, YARA rule matching, and cross-tool verification. All identifiers align with the sample's confirmed classification as Lumma Stealer (LummaC2) malware per multi-pipeline consensus.

| Attribute | Value | Source |
|-----------|-------|--------|
| SHA256 Hash | 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 | MalCat static analysis, cross-verified via YARA and capa rule matching (malcat, yara, capa) |
| File Path | /opt/samples/corpus
… [65827 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6901` | `10763989041e4877` |
| `prompt.txt` | `True` | `25949` | `7527811904c1dc12` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `40952` | `a481956238784fad` |
| `REPORT-MASTER-v3.md` | `True` | `68339` | `9a81649bf8fe25e0` |
| `REPORT-v2.md` | `True` | `40952` | `a481956238784fad` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `75836` | `da2de5f0a0da646f` |
| `rule.yar` | `True` | `1070` | `4ddd751c873ff5af` |
| `intake-validation.json` | `True` | `2951` | `b319595af3654396` |
| `source-decisions.json` | `True` | `2078` | `07c4adce0aa07b76` |
| `malcat-triage.json` | `True` | `55483` | `8d1328563e91ca9f` |
| `deep_dive/01-tools-raw.json` | `True` | `129754` | `0e5fe6ecb0a1dc40` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3679` | `1dd73e84e53cdc6b` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `122915` | `654614a013c5f2e0` |

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

- **intake_validation:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/intake-validation.json` exists=`True` bytes=`2951` mtime=`2026-08-04T04:31:43.884400+00:00`
  - sha256: `b319595af3654396a2a72c77f6ed7f3ceb9d249602529f78adfc6615dba73e1c`
- **malcat_triage:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/malcat-triage.json` exists=`True` bytes=`55483` mtime=`2026-08-04T04:31:07.219301+00:00`
  - sha256: `8d1328563e91ca9f58c945f345ba9e3b8f65c10365d9369128bcfb6faf924af6`
- **source_decisions:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/source-decisions.json` exists=`True` bytes=`2078` mtime=`2026-08-04T04:31:43.884400+00:00`
  - sha256: `07c4adce0aa07b7686a3e8a14ebccdded4f843ca2d21f341ae412d2c6496e516`
- **ghidra_import_log:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable (validation failed per warning, empty IDA summary) with 0 imports, while Ghidra reports 172 imports (ghidra, imports, 172) aligning with Malcat's import count (malcat, imports_count, 172), so Ghidra is selected as the import source."
  },
  "functions": {
    "source": "none",
    "confidence": "medium",
    "reason": "Ghidra reports 0 functions (ghidra, funcs, 0), IDA is unavailable (empty summary, validation failed per warning), and while Malcat reports 10 functions (malcat, functions_count, 10), primary reverse engineering tool function coverage is unreliable, so no valid function source exists."
  },
  "st
… [1301 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "file_name": "lumma_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
    "file_size": 1142333,
    "type": "PE",
    "architecture": "X86",
    "entropy": 216,
    "sha256": "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
    "metadata": {
      "Certificate::Issuer": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 202
… [54683 more chars]
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
  "rule_count": 41,
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
      "name": "log keystrokes via polling",
      "attack": [
        {
          "parts": [
            "Collection",
            "Input Capture",
            "Keylogging"
          ],
          "tactic": "Collection",
          "technique": "Input Capture",
          "subtechnique": "Keylogging",
          "id": "T1056.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Collection",
            "Keylogging",
            "Polling"
          ],
          "objective": "Collection",
          "behavior": "Keylogging",
          "method": "Polling",
          "id": "F0002.002"
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
      "name": "query environment variable",
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
  
… [6544 more chars]
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
  "duration_s": 27.81,
  "size_bytes": 1142333,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "file_name": "lumma_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
    "file_size": 1142333,
    "type": "PE",
    "architecture": "X86",
    "entropy": 216,
    "sha256": "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
    "metadata": {
      "Certificate::Issuer": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 (Organization=DigiCert, Inc. / Unit=? / Country=US)",
      "Certificate::Subject": "Mozilla Corporation",
      "Certificate::Org Details": "Mozilla Corporation / Unit=Firefox Engineering Operations / State=California / Locality=San Francisco / Country=US / Email=?",
      "Certificate::Validity": "from 2025-01-09 to 2027-01-08",
      "Certificate::SerialNumber": "0f0ef7c2d819273e8c13f016d2e09b25",
      "Certificate::HashAlgorithm": "SHA256",
      "Certificate::CryptAlgorithm": "RSA"
    },
    "entrypoint_ea": 11747,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 124
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 28672,
        "virtual_size": 28672,
        "rights": "RX",
        "entropy": 143
      },
      {
        "name": ".rdata",
        "effective_address": 29696,
        "physical_size": 11264,
        "virtual_size": 12288,
        "rights": "R",
        "entropy": 84
      },
      {
        "name": ".data",
        "effective_address": 41984,
        "physical_size": 512,
        "virtual_size": 425984,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".rsrc",
        "effective_address": 467968,
        "physical_size": 4608,
        "virtual_size": 28672,
        "rights": "R",
        "entropy": 176
      },
      {
        "name": ".reloc",
        "effective_address": 496640,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": "overlay",
        "effective_address": 500736,
        "physical_size": 1092157,
        "virtual_size": 0,
        "rights": "",
        "entropy": 222
      },
      {
        "name": ".ndata",
        "effective_address": 1592893,
        "physical_size": 0,
        "virtual_size": 675840,
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
        "name": "InvalidSizeOfInitializ
… [86780 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 9,
  "hits": 9,
  "misses": [],
  "hit_examples": [
    "Certificate::Subject = Mozilla Corporation file_summary.metadata The sample is signed with a valid but likely stolen Dig",
    "XorInLoop\u00d74 (code), HighEntropy (entropy), HasOverlay (YARA) anomalies Multiple XOR loops in code indicate obfuscation/e",
    "label: set_registry_value (RegSetValue API, ATT&CK T1112) signals Registry modification capabilities are used by Lumma t",
    "name: log keystrokes via polling (ATT&CK T1056.001) top_rules Keylogging is a core Lumma Stealer capability used to capt",
    "name: encode data using XOR (ATT&CK T1027) top_rules XOR encoding is used to obfuscate stolen data prior to exfiltration"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious (Lumma Stealer info-stealing malware)",
  "family": "Lumma Stealer (LummaC2)",
  "score": 9,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "Certificate::Subject = Mozilla Corporation",
      "why": "The sample is signed with a valid but likely stolen DigiCert code signing certificate issued to Mozilla Corporation, a common tactic used by Lumma Stealer operators to bypass Windows SmartScreen and endpoint security trust checks."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d74 (code), HighEntropy (entropy), HasOverlay (YARA)",
      "why": "Multiple XOR loops in code indicate obfuscation/encoding of exfiltrated data, overall entropy of 216 and a 1MB+ high-entropy overlay confirm the sample is packed/encrypted to hide malicious functionality, a standard characteristic of Lumma Stealer."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "label: set_registry_value (RegSetValue API, ATT&CK T1112)",
      "why": "Registry modification capabilities are used by Lumma to persist, steal stored credentials from Windows registry hives, and disable security software."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "name: log keystrokes via polling (ATT&CK T1056.001)",
      "why": "Keylogging is a core Lumma Stealer capability used to capture user input including login credentials, payment details, and cryptocurrency wallet information."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "name: encode data using XOR (ATT&CK T1027)",
      "why": "XOR encoding is used to obfuscate stolen data prior to exfiltration to avoid detection by network monitoring and endpoint security tools."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rules: keylogger, win_registry, win_files_operation",
      "why": "These YARA rule matches directly confirm the sample implements keylogging, Windows registry manipulation, and file system operation capabilities consistent with info-stealing malware."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "APIs: OpenProcessToken, EnumProcesses, EnumProcessModules",
      "why": "These process enumeration APIs are used by Lumma to identify and target running processes for browsers, password managers, and cryptocurrency wallets to extract stored sensitive data."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_406321 (registry hive resolver function)",
      "why": "This function maps Windows registry hive constants to human-readable names, confirming the sample interacts with the registry to steal or modify sensitive user and system data."
    },
    {
      "source": "malcat",
      "query_or_table": "carved_files",
      "row_or_rule": "NSIS@523776 (1055469 bytes)",
      "why": "The large NSIS installer overlay indicates the sample acts as a dropper for the Lumma Stealer payload, a common distribution method for the malware family."
    }
  ],
  "summary": "This is a packed, high-entropy Lumma Stealer info-stealing malware sample, disguised as a legitimate Mozilla-signed executable. It exhibits core Lumma capabilities including keylogging, registry manipulation, process enumeration, file system discovery, XOR obfuscation of exfiltrated data, and acts as a dropper for an NSIS-packed payload stored in its file overlay. The sample uses a stolen DigiCert"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/prompt.txt` exists=`True` bytes=`25949` mtime=`2026-08-04T04:32:20.428899+00:00`
  - sha256: `7527811904c1dc12d8eb3c8117980427233f0d3c8b0cefc8150cf9e7e1377840`
- **verdict:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/verdict.json` exists=`True` bytes=`6901` mtime=`2026-08-04T04:32:46.566699+00:00`
  - sha256: `10763989041e4877171617f2e13bfe61b38d6a17a47d1504f804469f3784c0e2`

#### prompt_excerpt

```
# Triage evidence
sha256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50
sample_path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe
ghidra_session: ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50
ida_session: ida-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA is unavailable (validation failed per warning, empty IDA summary) with 0 imports, while Ghidra reports 172 imports (ghidra, imports, 172) aligning with Malcat's import count (malcat, imports_count, 172), so Ghidra is selected as the import source.
- functions: none (confidence=medium) — Ghidra reports 0 functions (ghidra, funcs, 0), IDA is unavailable (empty summary, validation failed per warning), and while Malcat reports 10 functions (malcat, functions_count, 10), primary reverse engineering tool function coverage 
… [24926 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious (Lumma Stealer info-stealing malware)",
  "score": 9,
  "family_guess": "Lumma Stealer (LummaC2)",
  "cross_engine_notes": [
    "IDA is fully unavailable: the idasql binary is missing, so all IDA-derived analysis queries fail and no IDA data is present.",
    "Ghidra reports 0 disassembled functions, while Malcat reports 15 functions and provides decompilations for 3 top functions; Ghidra's 0 function count is likely an artifact of packing/obfuscation that prevents automatic function detection.",
    "Import counts are closely aligned: Ghidra reports 172 imports, Malcat and pe_imports report 171 imports. Per intake validation, Ghidra is selected as the authoritative import source due to higher reported count and alignment with Malcat's import count.",
    "String counts differ: Ghidra reports 180 strings, Malcat reports 100 strings. Per intake validation, both sources are combined to maximize string coverage with no data conflicts.",
    "The sample is signed
… [5901 more chars]
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
  "rule_count": 41,
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
      "name": "log keystrokes via polling",
      "attack": [
        {
          "parts": [
            "Collection",
            "Input Capture",
            "Keylogging"
          ],
          "tactic": "Collection",
          "technique": "Input Capture",
          "subtechnique": "Keylogging",
          "id": "T1056.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Collection",
            "Keylogging",
            "Polling"
          ],
          "objective": "Collection",
          "behavior": "Keylogging",
          "method": "Polling",
          "id": "F0002.002"
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
      "name": "query environment variable",
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
  
… [6543 more chars]
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
  "duration_s": 25.77,
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
  "checked": 4,
  "hits": 4,
  "misses": [],
  "hit_examples": [
    "IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDigitalSignature, HasRichSignature, Nullsoft_PiMP_Stub_SFX yara_match_rul",
    "domain, $ipv4, $ipv6, $url_regex, contains_base64 yara_match_rules Matched rules detect embedded C2 infrastructure indic",
    "escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation yara_match_rules Matched rules identi",
    "sample_path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample."
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "The sample is a packed Windows PE32 GUI executable belonging to the Lumma info-stealer malware family. It contains embedded command-and-control (C2) indicators (domains, IPv4/IPv6 addresses, URLs, base64-encoded data) and implements malicious capabilities including privilege escalation, screenshot c",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_match_rules",
      "row_or_rule": "IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDigitalSignature, HasRichSignature, Nullsoft_PiMP_Stub_SFX",
      "why": "These matched YARA rules confirm the sample is a packed Windows GUI PE executable with a digital signature, standard PE rich header, Nullsoft SFX stub, and embedded overlay, all common traits of packed malware."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_match_rules",
      "row_or_rule": "domain, $ipv4, $ipv6, $url_regex, contains_base64",
      "why": "Matched rules detect embedded C2 infrastructure indicators including network domains, IPv4 and IPv6 addresses, URLs, and base64-encoded data used for malicious command and control communication."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_match_rules",
      "row_or_rule": "escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation",
      "why": "Matched rules identify core malicious capabilities consistent with info-stealing malware: privilege escalation, screen capture, keystroke logging, Windows registry modification, security token theft, and unauthorized file system operations, all characteristic of the Lumma info-stealer family."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "sample_metadata",
      "row_or_rule": "sample_path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "why": "The sample filename explicitly references the Lumma info-stealer family, a known malicious infostealer, corroborating the YARA capability matches."
    }
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

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
    "file_name": "lumma_sample.exe",
    
… [90089 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 41,
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
… [9643 more chars]
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
   
… [1673 more chars]
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
  "session_id": "ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "audit_path": "/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/audit.jsonl"
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
      "name": "SetFileTime",
      "module": "KERNEL32.DLL",
      "address": "1"
    },
    {
      "name": "CompareFileTime",
      "module": "KERNEL32.DLL",
      "address": "2"
    },
    {
      "name": "SearchPathW",
      "module": "KERNEL32.DLL",
      "address": "3"
    },
    {
      "name": "GetShortPathName
… [4863 more chars]
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
      "content": "GetTempPathW",
      "address": "4235748",
      "length": "13"
    },
    {
      "content": "GetTempFileNameW",
      "address": "4235946",
      "length": "17"
    },
    {
      "content": "SystemParametersInfoW",
      "address": "4237076",
      "length": "22"
    },
    {
      "content": "<
… [1119 more chars]
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
  "session_id": "ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "audit_path": "/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/audit.jsonl"
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
      "name": "SetFileTime",
      "module": "KERNEL32.DLL",
      "address": "1"
    },
    {
      "name": "CompareFileTime",
      "module": "KERNEL32.DLL",
      "address": "2"
    },
    {
      "name": "SearchPathW",
      "module": "KERNEL32.DLL",
      "address": "3"
    },
    {
      "name": "GetShortPathName
… [4863 more chars]
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
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
      "content": "KERNEL32.dll",
      "address": "4236152",
      "length": "13"
    },
    {
      "content": "USER32.dll",
      "address": "4237274",
      "length": "11"
    },
    {
      "content": "GDI32.dll",
      "address": "4237420",
      "length": "10"
    },
    {
      "content": "SHELL32.dll",
     
… [1571 more chars]
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
  "session_id": "ghidra-pe-706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "audit_path": "/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/audit.jsonl"
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
      "name": "RegEnumKeyW",
      "module": "ADVAPI32.DLL",
      "address": "153"
    },
    {
      "name": "RegOpenKeyExW",
      "module": "ADVAPI32.DLL",
      "address": "154"
    },
    {
      "name": "RegCloseKey",
      "module": "ADVAPI32.DLL",
      "address": "155"
    },
    {
      "name": "RegDeleteKey
… [4885 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/01-tools-raw.json` exists=`True` bytes=`129754` mtime=`2026-08-04T04:33:27.278198+00:00`
  - sha256: `0e5fe6ecb0a1dc409aa0023a42a282301883c28eb30e826ab97e10ab3c39b657`
- **sql_evidence:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/05-deep-dive.json` exists=`True` bytes=`3679` mtime=`2026-08-04T04:34:28.884096+00:00`
  - sha256: `1dd73e84e53cdc6b45971e496a3e2965ab95d56e1f8c367b7c5a9f302722cdcc`

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
  "summary": "The sample is a packed Windows PE32 GUI executable belonging to the Lumma info-stealer malware family. It contains embedded command-and-control (C2) indicators (domains, IPv4/IPv6 addresses, URLs, base64-encoded data) and implements malicious capabilities including privilege escalation, screenshot capture, keylogging, Windows registry manipulation, security token theft, and file system operations. The sample has a valid digital signature, a standard PE rich header, a Nullsoft PiMP self-extracting stub, and an embedded overlay consistent with packed malicious content.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_match_rul
… [2879 more chars]
```

- **agentic:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`355118` mtime=`2026-08-04T04:34:28.884096+00:00`
  - sha256: `a4f6a45d340e642a6ff463ec261c5ceda4a80442d510f15f3d2deb76270ae7af`

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

- **rule_yar:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/rule.yar` exists=`True` bytes=`1070` mtime=`2026-08-04T04:38:11.911291+00:00`
  - sha256: `4ddd751c873ff5af78ef52acad9122da80875bdb7b8d805ebe77aa864ebb6451`

#### excerpt

```
// yara_gen_v2.py — 2026-08-04T04:38:11.911415+00:00
rule CADRE_v2_unknown_706a49b55ba7 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "WritePrivateProfileStringW" ascii wide
        $s1 = "SHGetSpecialFolderLocation" ascii wide
        $s2 = "ExpandEnvironmentStringsW" ascii wide
        $s3 = "GetPrivateProfileStringW" ascii wide
        $s4 = "GetFileVersionInfoSizeW" ascii wide
        $s5 = "SystemParametersInfoW" ascii wide
        $s6 = "SetCurrentDirectoryW" ascii wide
        $s7 = "GetWindowsDirectoryW" ascii wide
        $s8 = "SHGetPat
… [268 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-MASTER-v2.md` exists=`True` bytes=`40952` mtime=`2026-08-04T04:36:48.382293+00:00`
  - sha256: `a481956238784fad6a002f1b82dd40de50249a8892c61c29d2caf7af319ea899`
- **REPORT_MASTER_v3:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-MASTER-v3.md` exists=`True` bytes=`68339` mtime=`2026-08-04T04:42:08.993786+00:00`
  - sha256: `9a81649bf8fe25e0d70f1febce7bf18a70cb1d5aeae5745fcd6bafc8650d792d`
- **REPORT_v2:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-v2.md` exists=`True` bytes=`40952` mtime=`2026-08-04T04:36:48.382293+00:00`
  - sha256: `a481956238784fad6a002f1b82dd40de50249a8892c61c29d2caf7af319ea899`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`75738` mtime=`2026-08-04T04:38:04.491691+00:00`
  - sha256: `6ad7158264eb6c71dd5b50df97e7817f4b91e79687370becded8b7c13ed1dd72`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`75836` mtime=`2026-08-04T04:44:07.972883+00:00`
  - sha256: `da2de5f0a0da646f73126946d88530fc8fadc76fe7430ba3d2c990aae19d4265`
- **report_v2_json:** `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/report-v2.json` exists=`True` bytes=`43591` mtime=`2026-08-04T04:38:04.497991+00:00`
  - sha256: `9f2c7c813b06b17147f8e132dfc94ef9e4cb7abdde6b079fd4c5abc3eeb5a47e`

#### v2_excerpt

```
# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious (Lumma Stealer info-stealing malware) |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report analyzes a malicious Windows PE32 GUI executable (SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`) identified as Lumma Stealer (LummaC2), a commodity info-stealing malware. The sample received a triage score of 9/10 for maliciousness, with 90% confidence in family classification. Key findings include: the sample is packed with high entropy (7.16 bits/byte, well above the 6.0 threshold for packed executables) and signed with a valid but likely stolen DigiCert code signing certificate issued to Mozilla Corporation, a co
… [40046 more chars]
```


#### v3_excerpt

```
# RE Report — 706a49b55ba7
_Generated 2026-08-04T04:42:08.991892+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=288c | cross_refs=True | llm_ok=True | runtime=25.98s -->

## Executive Summary
| Metric | Value |
|--------|-------|
| Verdict | Malicious |
| Malware Family | Lumma Stealer (LummaC2) |
| Confidence | 90% |
| Analysis Agreement | LLM and v1 scoring systems concur |
| Core Validation Signals | 19 YARA rule matches, 41 capa capability rule matches, v1 malicious score of 290 |

The analyzed 32-bit x86 Windows Portable Executable (PE) sample (SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50`) is definitively classified as **Malicious**, attributed to the *Lumma Stealer (LummaC2)* info-stealing malware family with 90% confi
… [67427 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
