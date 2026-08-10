# Pipeline AUDIT-REPORT — `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:27.497147+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:27 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Suspicious` confidence=`35`
- key_evidence_count=`9`

```json
{
  "verdict": "Suspicious",
  "score": 35,
  "family_guess": "Unknown (masqueraded/modified Inno Setup installer, potential malicious delivery vehicle but no confirmed malicious payload)",
  "cross_engine_notes": "IDA reports 2086 functions vs Ghidra's 3 due to heavy obfuscation and stripped symbols, consistent with Malcat's obfuscation anomalies (spaghetti functions, XOR loops, high cross-reference looping). Import data is consistent across IDA, Malcat, and pe_imports, confirming privilege escalation, registry, and process manipulation APIs. YARA Delphi/InnoSetup/TurboLinker rules align with Malcat's metadata identifying the sample as a Delphi-built Inno Setup installer, and FLOSS strings contain Delphi RTL type names confirming the development framework.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "Certificate::Subject = 'Zhengzhou Lichang Network Technology Co., Ltd.' vs VersionInfo::CompanyName = 'Pringle'",
      "why": "Code signing certificate subject does not match the claimed software vendor, indicating potential masquerade of the installer's origin."
    },
    {
      "source": "malcat",
      "query_or_table": "matches",
      "row_or_rule": "Delphi, InnoInstaller, TurboLinker",
      "why": "These rules confirm the sample is built with Delphi and Inno Setup, aligning with Malcat's metadata and explaining the observed Delphi RTL strings and installer structure.",
      "source_corrected_from": "yara"
    },
    {
      "source": "yara",
      "query_or_table": "rule: escalate_priv",
      "row_or_rule": "escalate_priv match",
      "why": "Indicates presence of privilege escalation functionality, a capability commonly abused by malicious software to gain elevated system access."
    },
    {
      "source": "ghidra",
      "query_or_table": "imports",
      "row_or_rule": "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW, advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW",
      "why": "These APIs are used to modify process token privileges, enabling privilege escalation, a hostile behavioral capability.",
      "source_corrected_from": "ida"
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "ATT&CK T1012: Query Registry",
      "why": "Confirms the sample performs registry enumeration/modification, a tactic used for persistence, configuration tampering, or credential theft."
    },
    {
      "source": "ghidra",
      "query_or_table": "imports",
      "row_or_rule": "advapi32.RegOpenKeyExW, advapi32.RegQueryValueExW",
      "why": "These APIs are used to access and query the Windows registry, confirming registry manipulation capabilities.",
      "source_corrected_from": "ida"
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_40ab18",
      "why": "Decompiled code shows explicit calls to RegOpenKeyExW to access HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER registry hives, confirming registry manipulation behavior in practice."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d719, SpaghettiFunction\u00d730, HighXrefLoopingFunction\u00d712",
      "why": "These anomalies indicate heavy obfuscation/packing, which is a neutral signal but increases suspicion when combined with other suspicious indicators."
    },
    {
      "source": "pe_imports",
      "query_or_
… [3782 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`14`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This is a packed/obfuscated Windows PE with strong malicious indicators. Deterministic tool outputs show: YARA hits for domain/IP/URL/base64/CRC32/Delphi-Borland signatures and packed/overlay characteristics; capa identifies obfuscation (XOR, RC4), execution via command-line args, process injection (VirtualProtect/VirtualAlloc), registry/service/screenshot/keylog behaviors; PE import signals include CreateProcess, LoadLibrary/GetProcAddress, VirtualProtect, VirtualAlloc, with no imports associated with exfiltration or defense_impairment functionality present {PE static import analysis, import table enumeration, observed imports: CreateProcess, LoadLibrary/GetProcAddress, VirtualProtect, VirtualAlloc; no exfiltration/defense_impairment associated imports detected, why: no APIs for data exfiltration or defensive countermeasure execution are present in the import table}; FLOSS reveals Delphi RTTI/type strings; Ghidra reports only 3 functions while IDA reports 2086, indicating severe control-flow or symbol obfuscation typical of malware. Exfiltration capabilities are not observed across all analyzed tool outputs {capa capability detection, behavior rule set, no exfiltration-related capability rules triggered; FLOSS string extraction, extracted string corpus, no exfiltration-related strings (e.g., C2 exfil endpoints, upload routine markers) identified; IDA disassembly, function cross-reference analysis, no exfiltration routine implementations found, why: no evidence of data exfiltration, C2 data transfer, or file/credential staging functionality exists in the analyzed artifact}. Defense_impairment capabilities are not observed {capa capability detection, behavior rule set, no defense_impairment-related capability rules triggered; PE static import analysis, import table enumeration, no defense_impairment associated imports (e.g., AdjustTokenPrivileges, antivirus process termination APIs) present; Ghidra disassembly, function list analysis, no defense impairment routine implementations found, why: no evidence of antivirus tampering, log deletion, security service disabling, or other defensive countermeasure functionality exists in the analyzed artifact}.",
  "key_evidence": [
    "YARA rule 'domain' matched at offset 0",
    "YARA rule 'IP' matched at offsets 830343 and 917570",
    "YARA rule 'url' matched at offset 722888",
    "YARA rule 'contains_base64' matched at offset 2194",
    "YARA rule 'CRC32_poly_Constant' matched at offset 146170",
    "YARA rules 'Borland'/'borland_delphi'/'Borland_Delphi_40_additional' matched",
    "YARA rules 'IsPacked' and 'HasOverlay' matched",
    "capa rule 'encode data using XOR' (T1027) matched",
    "capa rule 'encrypt data using RC4 PRGA' matched",
    "capa rules for 'accept command line arguments', 'query environment variable', 'create process', 'inject process', 'modify registry', 'install service', 'capture screenshot', 'log keystrokes' matched",
    "pe_import_signals: CreateProcess (T1106), LoadLibrary/GetProcAddress (T1129), VirtualProtect/VirtualAlloc (T1055)",
    "FLOSS static strings include Delphi RTTI types: Boolean, System, AnsiString, WideString, Variant, TObject&, ClassName, VTable, etc.",
    "Ghidra funcs count=3 vs IDA funcs count=2086, indicating obfuscation/packing",
    "IDA top functions: sub_41AC0C (2641 bytes), sub_41C8C4 (2168 bytes), start (1635 bytes)"
  ]
… [1238 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (koi_sample.exe)",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-08 07:30:27 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Suspicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\nThis report analyzes the 32-bit x86 PE sample `koi_sample.exe` (SHA256: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819), identified as a masqueraded, obfuscated Inno Setup installer. Static analysis reveals a mismatch between the claimed software vendor (\"Pringle\" in version info) and the code signing certificate subject (\"Zhengzhou Lichang Network Technology Co., Ltd.\"), indicating potential origin masquerade (source: triage verdict). The sample exhibits heavy control-flow obfuscation (19 XOR-in-loop anomalies, 30 spaghetti functions, 12 high cross-reference looping functions per MalCat) and delay-load stubs for Windows system APIs (source: agentic_recover_v4). High-risk static capabilities include privilege escalation, registry manipulation, process creation, and memory manipulation (VirtualAlloc/VirtualProtect), which are commonly abused by malicious delivery vehicles (source: ghidra_query, pe_imports, capa). No confirmed malicious payload, C2 infrastructure, or runtime malicious behavior was identified in static analysis, but the combination of masquerade, obfuscation, and hostile capabilities warrants classification as Suspicious per upstream triage (source: triage verdict). Dynamic analysis is required to confirm the presence of a bundled payload or runtime malicious actions.\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 |\n| Sample Path | /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe |\n| Project Name | incoming |\n| File Type | PE32 (32-bit x86) (source: MalCat) |\n| Entropy | 7.184 (high, indicating obfuscation/packing) (source: MalCat) |\n| UPX Status | Not packed (UPX probe returned 0 files) (source: UPX unpack evidence) |\n| XOR Search Result | XOR 00 mask found at offset 0x0, recovering partial string \"This program must be r\" (consistent with Inno Setup loader message) (source: xorsearch evidence) |\n| Version Info | Product name: \"Pringle Setup\" (source: rule.yara.json strings) |\n| Code Signing Certificate Subject | Zhengzhou Lichang Network Technology Co., Ltd. (source: triage verdict) |\n\nThe sample is a 32-bit Windows PE file with high entropy, consistent with obfuscated or packed content, though UPX did not identify a UPX packer layer. The partial recovered XOR string matches the standard Inno Setup loader error message, confirming the sample is based on the Inno Setup installer framework. A critical discrepancy exists between the claimed vendor (\"Pringle\" in version metadata) and the code signing certificate issuer, indicating the sample is masqueraded to hide its true origin (source: triage verdict).\n\n## 2. Classification\n| Field | Value 
… [35833 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 07:30:27 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report analyzes the 32-bit x86 PE sample `koi_sample.exe` (SHA256: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819), identified as a masqueraded, obfuscated Inno Setup installer. Static analysis reveals a mismatch between the claimed software vendor ("Pringle" in version info) and the code signing certificate subject ("Zhengzhou Lichang Network Technology Co., Ltd."), indicating potential origin masquerade (source: triage verdict). The sample exhibits heavy control-flow obfuscation (19 XOR-in-loop anomalies, 30 spaghetti functions, 12 high cross-reference looping functions per MalCat) and delay-load stubs for Windows system APIs (source: agentic_recover_v4). High-risk static capabilities include privilege escalation, registry manipulation, process creation, and memory manipulation (VirtualAlloc/VirtualProtect), which are commonly abused by malicious delivery vehicles (source: ghidra_query, pe_imports, capa). No confirmed malicious payload, C2 infrastructure, or runtime malicious behavior was identified in static analysis, but the combination of masquerade, obfuscation, and hostile capabilities warrants classification as Suspicious per upstream triage (source: triage verdict). Dynamic analysis is required to confirm the presence of a bundled payload or runtime malicious actions.

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 |
| Sample Path | /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe |
| Project Name | incoming |
| File Type | PE32 (32-bit x86) (source: MalCat) |
| Entropy | 7.184 (high, indicating obfuscation/packing) (source: MalCat) |
| UPX Status | Not packed (UPX probe returned 0 files) (source: UPX unpack evidence) |
| XOR Search Result | XOR 00 mask found at offset 0x0, recovering partial string "This program must be r" (consistent with Inno Setup loader mess
… [33933 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 07:44:09 UTC

# RE Report — e29d2bd94621
_Generated 2026-08-08T07:44:09.326891+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=351c | cross_refs=True | llm_ok=True | runtime=37.94s -->

# Executive Summary
| Attribute | Value |
|-----------|-------|
| Sample SHA-256 | `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819` |
| Top-Line Verdict | Suspicious |
| Confidence | 90% |
| Family Affiliation | Unknown (masqueraded modified Inno Setup installer) |
| Initial v1 Verdict | Malicious (score: 290, 26 YARA matches, 37 capa rule matches) |

The analyzed sample is a 32-bit packed Windows GUI Portable Executable (PE) compiled in Borland Delphi, identified by its immutable SHA-256 hash `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819` (cross-section:1.sample_identification, sha256 field; cross-section:4.static_analysis, architecture field; cross-section:10.detection_rules, Borland/IsWindowsGUI/IsPacked match rows). Deep dive agentic analysis assesses the sample as Suspicious with 90% confidence, overriding an initial v1 assessment that labeled the sample as malicious with a score of 290, supported by 26 YARA rule matches and 37 capa rule alignments (deep_dive_agentic, verdict; deep_dive_agentic, deep_confidence; llm_v1_disagree; v1_summary, findings).

These initial rule matches are consistent with the sample's structure as a modified Inno Setup installer wrapper, and its import set including core Windows system libraries (`kernel32`, `netapi32`, `advapi32`, `oleaut32`, `user32`, `comctl32`, `version`) that align with generic loader functionality (cross-section:4.static_analysis, ImportNames/OFT/FT entries row; cross-section:7.capability_assessment, capa). No confirmed malicious payload was recovered from the sample during static analysis, Speakeasy emulation, or Frida dynamic instrumentation (cross-section:5.behavioral_analysis, capa and malcat citations). No hardcoded command-and-control (C2) infrastructure was identified in static or dynamic analysis (cross-section:6.network_analysis_c2, no_network_indicators_identified row), and no confirmed affiliation to known malware families or threat actors has 
… [48230 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7282` | `b91cb0b20290bf6b` |
| `prompt.txt` | `True` | `29783` | `fa749703d5699648` |
| `pipeline-audit.json` | `True` | `107257` | `1321e4dfbcb7394a` |
| `AUDIT-REPORT.md` | `True` | `80331` | `2ad9e396f56cbe6d` |
| `REPORT-MASTER-v2.md` | `True` | `36444` | `54e9c6694399ace3` |
| `REPORT-MASTER-v3.md` | `True` | `50745` | `9c4c4475230b25be` |
| `REPORT-v2.md` | `True` | `36444` | `54e9c6694399ace3` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `79965` | `5e815fb87d640e16` |
| `rule.yar` | `True` | `1640` | `1744332b42c393f6` |
| `intake-validation.json` | `True` | `2677` | `169bb5547f2c364a` |
| `source-decisions.json` | `True` | `1698` | `9fe65f1ea5c0765f` |
| `malcat-triage.json` | `True` | `89064` | `e2cde2a5fa3c4804` |
| `deep_dive/01-tools-raw.json` | `True` | `196492` | `acc66368a44d2b83` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4738` | `9929ab8b59ac6ead` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `182188` | `e34ab8f39ba51ee6` |

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

- **intake_validation:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/intake-validation.json` exists=`True` bytes=`2677` mtime=`2026-08-08T07:16:55.419639+00:00`
  - sha256: `169bb5547f2c364a68f61a6739bdf3342a7ec935c408681c1ae7f5adcbd46532`
- **malcat_triage:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/malcat-triage.json` exists=`True` bytes=`89064` mtime=`2026-08-08T07:16:26.464662+00:00`
  - sha256: `e2cde2a5fa3c48049954b3577b466f72018b32aef16761aa9986936ec2a9fdc7`
- **source_decisions:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/source-decisions.json` exists=`True` bytes=`1698` mtime=`2026-08-08T07:16:55.419639+00:00`
  - sha256: `9fe65f1ea5c0765f98dce77b275fe317798407e7ccf2325ee4a68fcc44c0a309`
- **ghidra_import_log:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/intake-analyzeHeadless.log` exists=`True` bytes=`6556` mtime=`2026-08-04T05:10:59.359421+00:00`
  - sha256: `24814ea898dd8751fd57b993c565289a51ecbc2bce9849938276d58cc3a6c545`
- **ida_bootstrap_log:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/intake-idasql.log` exists=`True` bytes=`223` mtime=`2026-08-08T07:16:29.345659+00:00`
  - sha256: `4640e047ca57f9e308cb51c3ae52f8f45de1c2fc0b75671c2bd9eb8f733eb670`

#### source_decisions_excerpt

```
{
  "sha256": "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA both report 145 imports (within 20% agreement per tool summaries), while Malcat's import count (373) diverges significantly from disassembler outputs, so Ghidra is selected as the source."
  },
  "functions": {
    "source": "review",
    "confidence": "medium",
    "reason": "Ghidra reports 3 functions while IDA reports 2086, a divergence >2x (ratio ~0.0014) per tool summaries and warnings, making automated tool output unreliable, requiring manual review."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "IDA (9989 strings) and Ghidra (360 strings) provide complementary string dat
… [921 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "file_name": "koi_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
    "file_size": 2263752,
    "type": "PE",
    "architecture": "X86",
    "entropy": 184,
    "sha256": "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
    "metadata": {
      "Certificate::Issuer": "Certum Extended Validation Code Signing 2021 CA (Organiza
… [88264 more chars]
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
  "rule_count": 37,
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
          "technique": "File an
… [5542 more chars]
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
  "duration_s": 130.78,
  "size_bytes": 2263752,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "file_name": "koi_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
    "file_size": 2263752,
    "type": "PE",
    "architecture": "X86",
    "entropy": 184,
    "sha256": "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
    "metadata": {
      "Certificate::Issuer": "Certum Extended Validation Code Signing 2021 CA (Organization=Asseco Data Systems S.A. / Unit=? / Country=PL)",
      "Certificate::Subject": "Zhengzhou Lichang Network Technology Co., Ltd.",
      "Certificate::Org Details": "Zhengzhou Lichang Network Technology Co., Ltd. / Unit=? / State=Henan / Locality=Zhengzhou / Country=CN / Email=?",
      "Certificate::Org Serial Number": "91410122MA40Y0N9XP",
      "Certificate::Validity": "from 2024-11-21 to 2025-11-21",
      "Certificate::SerialNumber": "04ebda42bf9235aecf2e07587ec4623f",
      "Certificate::HashAlgorithm": "SHA256",
      "Certificate::CryptAlgorithm": "RSA",
      "Delphi::ProjectName": "SetupLdr",
      "VersionInfo::Comments": "This installation was built with Inno Setup.",
      "VersionInfo::CompanyName": "Pringle                                                     ",
      "VersionInfo::FileDescription": "Pringle Setup                                               ",
      "VersionInfo::FileVersion": "                    ",
      "VersionInfo::LegalCopyright": "                                                                                                    ",
      "VersionInfo::OriginalFileName": "                                                  ",
      "VersionInfo::ProductName": "Pringle                                                     ",
      "VersionInfo::ProductVersion": "2.2                                               ",
      "Exports::Module name": "SetupLdr.exe"
    },
    "entrypoint_ea": 742124,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 101
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 735744,
        "virtual_size": 737280,
        "rights": "RX",
        "entropy": 121
      },
      {
        "name": ".itext",
        "effective_address": 738304,
        "physical_size": 6144,
        "virtual_size": 8192,
        "rights": "RX",
        "entropy": 48
      },
      {
        "name": ".data",
        "effective_address": 746496,
        "physical_size": 14336,
        "virtual_size": 16384,
        "rights": "RW",
        "entropy": 82
      },
      {
        "name": ".idata",
        "effective_address": 762880,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 74
      },
      {
        "name": ".didata",
        "effective_address": 766976,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".edata",
        "effective_address": 771072,
        "physical_size": 512,
        "virtu
… [140216 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 9,
  "hits": 9,
  "misses": [],
  "hit_examples": [
    "Certificate::Subject = 'Zhengzhou Lichang Network Technology Co., Ltd.' vs VersionInfo::CompanyName = 'Pringle' file_sum",
    "Delphi, InnoInstaller, TurboLinker matches These rules confirm the sample is built with Delphi and Inno Setup, aligning ",
    "escalate_priv match rule: escalate_priv Indicates presence of privilege escalation functionality, a capability commonly ",
    "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW, advapi32.ConvertStringSecurityDescriptorToSecurityDescri",
    "ATT&CK T1012: Query Registry top_rules Confirms the sample performs registry enumeration/modification, a tactic used for"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Suspicious",
  "family": "Unknown (masqueraded/modified Inno Setup installer, potential malicious delivery vehicle but no confirmed malicious payload)",
  "score": 35,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "Certificate::Subject = 'Zhengzhou Lichang Network Technology Co., Ltd.' vs VersionInfo::CompanyName = 'Pringle'",
      "why": "Code signing certificate subject does not match the claimed software vendor, indicating potential masquerade of the installer's origin."
    },
    {
      "source": "malcat",
      "query_or_table": "matches",
      "row_or_rule": "Delphi, InnoInstaller, TurboLinker",
      "why": "These rules confirm the sample is built with Delphi and Inno Setup, aligning with Malcat's metadata and explaining the observed Delphi RTL strings and installer structure.",
      "source_corrected_from": "yara"
    },
    {
      "source": "yara",
      "query_or_table": "rule: escalate_priv",
      "row_or_rule": "escalate_priv match",
      "why": "Indicates presence of privilege escalation functionality, a capability commonly abused by malicious software to gain elevated system access."
    },
    {
      "source": "ghidra",
      "query_or_table": "imports",
      "row_or_rule": "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW, advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW",
      "why": "These APIs are used to modify process token privileges, enabling privilege escalation, a hostile behavioral capability.",
      "source_corrected_from": "ida"
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "ATT&CK T1012: Query Registry",
      "why": "Confirms the sample performs registry enumeration/modification, a tactic used for persistence, configuration tampering, or credential theft."
    },
    {
      "source": "ghidra",
      "query_or_table": "imports",
      "row_or_rule": "advapi32.RegOpenKeyExW, advapi32.RegQueryValueExW",
      "why": "These APIs are used to access and query the Windows registry, confirming registry manipulation capabilities.",
      "source_corrected_from": "ida"
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_40ab18",
      "why": "Decompiled code shows explicit calls to RegOpenKeyExW to access HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER registry hives, confirming registry manipulation behavior in practice."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d719, SpaghettiFunction\u00d730, HighXrefLoopingFunction\u00d712",
      "why": "These anomalies indicate heavy obfuscation/packing, which is a neutral signal but increases suspicion when combined with other suspicious indicators."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_process (CreateProcess)",
      "why": "The sample can create new processes, a capability used by both legitimate installers and malicious payloads for execution of additional code."
    }
  ],
  "summary": "This is a 32-bit x86 Delphi-based Inno Setup installer with heavy obfuscation (evidenced by spaghetti control flow, XOR encoding loops, and high cross-reference looping anomalies) and a valid code signing certificate that does not match its claimed vendor ('Pringle' in version info vs 'Zhengzhou Lichang Network Technology Co., Ltd.' on the certificate). It exhibits capabilities for privilege escal"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/prompt.txt` exists=`True` bytes=`29783` mtime=`2026-08-08T07:19:13.287802+00:00`
  - sha256: `fa749703d5699648dda4dc3319bf8e4f843ef851efdac923e7ffa84d744e7575`
- **verdict:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/verdict.json` exists=`True` bytes=`7282` mtime=`2026-08-08T07:20:20.268507+00:00`
  - sha256: `b91cb0b20290bf6b67ca66dfc31b1391e57c75fb38bfe7288bfd3468bbc4dee4`

#### prompt_excerpt

```
# Triage evidence
sha256: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
sample_path: /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe
ghidra_session: ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
ida_session: ida-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA both report 145 imports (within 20% agreement per tool summaries), while Malcat's import count (373) diverges significantly from disassembler outputs, so Ghidra is selected as the source.
- functions: review (confidence=medium) — Ghidra reports 3 functions while IDA reports 2086, a divergence >2x (ratio ~0.0014) per tool summaries and warnings, making automated tool output unreliable, requiring manual review.
- strings: both (confidence=high) — IDA (9989 strings) and Ghidra (360 strings) provide complementar
… [28736 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Suspicious",
  "score": 35,
  "family_guess": "Unknown (masqueraded/modified Inno Setup installer, potential malicious delivery vehicle but no confirmed malicious payload)",
  "cross_engine_notes": "IDA reports 2086 functions vs Ghidra's 3 due to heavy obfuscation and stripped symbols, consistent with Malcat's obfuscation anomalies (spaghetti functions, XOR loops, high cross-reference looping). Import data is consistent across IDA, Malcat, and pe_imports, confirming privilege escalation, registry, and process manipulation APIs. YARA Delphi/InnoSetup/TurboLinker rules align with Malcat's metadata identifying the sample as a Delphi-built Inno Setup installer, and FLOSS strings contain Delphi RTL type names confirming the development framework.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "Certificate::Subject = 'Zhengzhou Lichang Network Technology Co., Ltd.' vs VersionInfo::CompanyName = 'Prin
… [6282 more chars]
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
  "rule_count": 37,
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
          "technique": "File an
… [5541 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 2263752,
  "duration_s": 0.04,
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
  "duration_s": 133.99,
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
  "checked": 14,
  "hits": 14,
  "misses": [],
  "hit_examples": [
    "YARA rule 'domain' matched at offset 0",
    "YARA rule 'IP' matched at offsets 830343 and 917570",
    "YARA rule 'url' matched at offset 722888",
    "YARA rule 'contains_base64' matched at offset 2194",
    "YARA rule 'CRC32_poly_Constant' matched at offset 146170"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This is a packed/obfuscated Windows PE with strong malicious indicators. Deterministic tool outputs show: YARA hits for domain/IP/URL/base64/CRC32/Delphi-Borland signatures and packed/overlay characteristics; capa identifies obfuscation (XOR, RC4), execution via command-line args, process injection ",
  "key_evidence": [
    "YARA rule 'domain' matched at offset 0",
    "YARA rule 'IP' matched at offsets 830343 and 917570",
    "YARA rule 'url' matched at offset 722888",
    "YARA rule 'contains_base64' matched at offset 2194",
    "YARA rule 'CRC32_poly_Constant' matched at offset 146170",
    "YARA rules 'Borland'/'borland_delphi'/'Borland_Delphi_40_additional' matched",
    "YARA rules 'IsPacked' and 'HasOverlay' matched",
    "capa rule 'encode data using XOR' (T1027) matched",
    "capa rule 'encrypt data using RC4 PRGA' matched",
    "capa rules for 'accept command line arguments', 'query environment variable', 'create process', 'inject process', 'modify registry', 'install service', 'capture screenshot', 'log keystrokes' matched",
    "pe_import_signals: CreateProcess (T1106), LoadLibrary/GetProcAddress (T1129), VirtualProtect/VirtualAlloc (T1055)",
    "FLOSS static strings include Delphi RTTI types: Boolean, System, AnsiString, WideString, Variant, TObject&, ClassName, VTable, etc.",
    "Ghidra funcs count=3 vs IDA funcs count=2086, indicating obfuscation/packing",
    "IDA top functions: sub_41AC0C (2641 bytes), sub_41C8C4 (2168 bytes), start (1635 bytes)"
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

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "file_name": "koi_sample.exe",
    "fil
… [143294 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 37,
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
… [8641 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 2263752,
  "duration_s": 0.04,
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
      "name": "DelayLoad_MessageBoxA",
      "address": "4208496",
      "size": "1"
    },
    {
      "name": "DelayLoad_GetLogicalProcessorInformation",
      "address": "4208632",
      "size": "1"
    },
    {
      "name": "DelayLoad_GetNativeSystemInfo",
      "address": "4252280",
      "size": "1"
    }
  ],
  "
… [297 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 2263752,
  "duration_s": 0.06,
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
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL",
      "address": "136"
    },
    {
      "name": "CallWindowProcW",
      "module": "USER32.DLL",
      "address": "108"
    },
    {
      "name": "CharLowerBuffW",
      "module": "USER32.DLL",
      "address": "107"
    },
    {
      "name": "C
… [4981 more chars]
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
      "content": "GetStartupInfoW",
      "address": "4991056",
      "length": "16"
    },
    {
      "content": "Insufficient RTTI available to support this operation",
      "address": "5068366",
      "length": "108"
    },
    {
      "content": "Operation not supported",
      "address": "5070970",
      "len
… [3192 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 37,
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
… [8641 more chars]
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
      "name": "DelayLoad_MessageBoxA",
      "address": "4208496",
      "size": "1"
    },
    {
      "name": "DelayLoad_GetLogicalProcessorInformation",
      "address": "4208632",
      "size": "1"
    },
    {
      "name": "DelayLoad_GetNativeSystemInfo",
      "address": "4252280",
      "size": "1"
    }
  ],
  "
… [297 more chars]
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
      "name": "sub_41AC0C",
      "address": "4303884",
      "size": "2641"
    },
    {
      "name": "sub_41C8C4",
      "address": "4311236",
      "size": "2168"
    },
    {
      "name": "start",
      "address": "4939500",
      "size": "1635"
    },
    {
      "name": "sub_42CAA8",
      "address": "4377256",
 
… [1760 more chars]
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
… [1521 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/01-tools-raw.json` exists=`True` bytes=`196492` mtime=`2026-08-08T07:22:46.236377+00:00`
  - sha256: `acc66368a44d2b8307e1d1664f7b1b9e1bf154fd2b1869efa7988ba67f6e2ef3`
- **sql_evidence:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/05-deep-dive.json` exists=`True` bytes=`4738` mtime=`2026-08-08T07:26:16.624300+00:00`
  - sha256: `9929ab8b59ac6eadcc56cf456fc6d9d14f64d4dd4cdc81cc1c644f17a8ab5888`

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
  "summary": "This is a packed/obfuscated Windows PE with strong malicious indicators. Deterministic tool outputs show: YARA hits for domain/IP/URL/base64/CRC32/Delphi-Borland signatures and packed/overlay characteristics; capa identifies obfuscation (XOR, RC4), execution via command-line args, process injection (VirtualProtect/VirtualAlloc), registry/service/screenshot/keylog behaviors; PE import signals include CreateProcess, LoadLibrary/GetProcAddress, VirtualProtect, VirtualAlloc, with no imports associated with exfiltration or defense_impairment functionality present {PE static import analysis, import table enumeration, observed imports: CreateProcess, LoadLibrary/GetProcAddress, 
… [3938 more chars]
```

- **agentic:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`538848` mtime=`2026-08-08T07:26:16.623300+00:00`
  - sha256: `900e7d237d3d2ee483a099c301d26125935c80dfc3808f3399a819b8712e0728`

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

- **rule_yar:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/rule.yar` exists=`True` bytes=`1640` mtime=`2026-08-08T07:27:28.386570+00:00`
  - sha256: `1744332b42c393f6e73b01fed7d7e8b5f8e9686a94fe1c73190b859cfe841443`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T07:27:28.387609+00:00
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
        $s0 = "No mapping for the Unicode character exists in the target multi-byte code page" ascii wide
        $s1 = "Cannot have multiple single cast observers added to the observers collection" ascii wide
        $s2 = "No single cast observer with ID %d was added to the observer collection" ascii wide
        $s3 = "No multi cast obser
… [838 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-MASTER-v2.md` exists=`True` bytes=`36444` mtime=`2026-08-08T07:30:27.167284+00:00`
  - sha256: `54e9c6694399ace3de1f31bdbbe6017c5449bbdef4b2d40112dcef94a32b97b3`
- **REPORT_MASTER_v3:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-MASTER-v3.md` exists=`True` bytes=`50745` mtime=`2026-08-08T07:44:09.336124+00:00`
  - sha256: `9c4c4475230b25be24288430683cfa0f2ed81c682259218c9cb080fe6250bbb4`
- **REPORT_v2:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-v2.md` exists=`True` bytes=`36444` mtime=`2026-08-08T07:30:27.166284+00:00`
  - sha256: `54e9c6694399ace3de1f31bdbbe6017c5449bbdef4b2d40112dcef94a32b97b3`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`88144` mtime=`2026-08-08T07:38:46.389160+00:00`
  - sha256: `dd77612a9d2135240980b40d97fdc7574d30cc160c0cb08e6641bc2dbd2c021b`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`79965` mtime=`2026-08-08T07:46:57.557341+00:00`
  - sha256: `5e815fb87d640e16cda9b05358c13b5acf1ac4ac5a681fa2339ea6b54f303052`
- **report_v2_json:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/report-v2.json` exists=`True` bytes=`39333` mtime=`2026-08-08T07:38:46.397160+00:00`
  - sha256: `7a25e1fc2f8e89d4fa00c265ef3501f694ca8250bf238705ebf282523eb21d97`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 07:30:27 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report analyzes the 32-bit x86 PE sample `koi_sample.exe` (SHA256: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819), identified as a masqueraded, obfuscated Inno Setup installer. Static analysis reveals a mismatch between the claimed software vendor ("Pringle" in version info) and the code signing certificate subject ("Zhengzhou Lichang Network Technology Co., L
… [35533 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 07:44:09 UTC

# RE Report — e29d2bd94621
_Generated 2026-08-08T07:44:09.326891+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=351c | cross_refs=True | llm_ok=True | runtime=37.94s -->

# Executive Summary
| Attribute | Value |
|-----------|-------|
| Sample SHA-256 | `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819` |
| Top-Line Verdict | Suspicious |
| Confidence | 90% |
| Family Affiliation | Unknown (masqueraded modified Inno Setup installer) |
| Initial v1 Verdict | Malicious (score: 290, 26 YARA matches, 37 capa rule matches) |

The anal
… [49830 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
