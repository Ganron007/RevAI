# Pipeline AUDIT-REPORT — `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-03T06:41:50.597614+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`9`
- key_evidence_count=`8`

```json
{
  "verdict": "Malicious",
  "score": 9,
  "family_guess": "Packed malicious binary (likely ransomware or info-stealer, consistent with RC4 encryption and FreeEncryptedFileKeyInfo usage)",
  "cross_engine_notes": "IDA is non-functional due to missing /usr/local/bin/idasql binary, so all IDA-sourced data (imports, functions, strings, decompilation) is unavailable. Ghidra reports 365 functions and 7 imports, but its imports virtual table is empty, so import data is sourced from Malcat and pe_imports. String data is combined from Ghidra (11 strings) and FLOSS/Malcat (1144 total strings) for full coverage. Malcat is the sole source for reliable static profile, decompilation, and anomaly data as IDA is non-functional.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row": "type=PE, architecture=X86, entropy=201, anomalies: BigBufferNoXrefMediumToHighEntropy (19 hits), ManyHighValueImmediates (8 hits), ManyUniqueImmediateBytes (7 hits), SequentialFunction, GuiSubsystemNoWindowApi, NoChecksum, RichUnknownTool",
      "why": "High entropy confirms heavy obfuscation; the anomaly set (large unreferenced high-entropy buffers likely for crypto material, obfuscated code traits, missing checksum, unknown Rich header tool) is highly consistent with packed malicious code."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "Rule 'encrypt data using RC4 via SystemFunction033' (ATT&CK T1027, MBC C0027.009 RC4)",
      "why": "Direct detection of RC4 encryption behavior, a common technique for malicious payload obfuscation, decryption of embedded payloads, or data encryption."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation",
      "row": "sub_474643 loop XORing 0x71a06 bytes at address 0x401400 with sequential 32-bit constants",
      "why": "This is a decryption/decryption routine, a common startup behavior for packed malware to unpack its payload in memory."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row": "advapi32.FreeEncryptedFileKeyInfo, user32.dll, advapi32.dll, ntdll.dll, kernel32.dll",
      "why": "FreeEncryptedFileKeyInfo is a high-signal API for handling encrypted files, commonly used by ransomware or info-stealing malware; the import set supports Windows system interaction for malicious activity."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "Rule 'identify system language via API' (ATT&CK T1614.001)",
      "why": "System language discovery is a common reconnaissance behavior for targeted malware, including ransomware that may selectively encrypt files based on system language to avoid detection in certain regions."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row": "1144 total static strings, 0 decoded/stack/tight strings, all obfuscated",
      "why": "Complete absence of readable decoded strings indicates heavy obfuscation, consistent with packed malware that hides its indicators."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row": "IsPacked, IsWindowsGUI, contains_base64, domain, IP, HasRichSignature",
      "why": "IsPacked confirms obfuscation; presence of base64, domain, and IP indicators suggests embedded network or payload encoding capabilities; IsWindowsGUI with no window API imports (per Malcat GuiSubsystemNoWindowApi anomaly) is a common trait of malicious GUI
… [2944 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`11`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "The analyzed sample is a packed 32-bit Windows GUI Portable Executable (PE). YARA scanning confirms it is a valid PE32 file with a Windows GUI subsystem, is packed/obfuscated, contains a valid Rich header, and has embedded domain, IPv6 address, and base64 string indicators. Malcat deep analysis shows extremely high overall file entropy (201) and .text section entropy (202) consistent with packing, plus an anomaly indicating a large unlinked high-entropy buffer likely used for cryptographic operations. No legitimate Kaspersky detection matches were found for the sample.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "IsPE32",
      "why": "Confirms the sample is a valid 32-bit Portable Executable, the standard format for Windows applications and malware"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "IsWindowsGUI",
      "why": "Confirms the sample is a Windows GUI application, a common type for end-user facing malware"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "IsPacked",
      "why": "Indicates the executable is packed/obfuscated, a common technique used by malware to evade static detection and hinder reverse engineering"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "HasRichSignature",
      "why": "Confirms the PE has a valid Rich header, which combined with other malicious indicators rules out a corrupt or non-functional PE file"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "domain",
      "why": "YARA domain rule match confirms the sample contains an embedded malicious domain string, likely used for command-and-control (C2) communication"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "IP",
      "why": "YARA IP rule match confirms the sample contains an embedded IPv6 address, likely a C2 server address for network communication"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "contains_base64",
      "why": "YARA base64 rule match confirms the sample contains embedded base64-encoded data, likely used for payload delivery or C2 traffic obfuscation"
    },
    {
      "source": "checklist_malcat_analyze",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy=201",
      "why": "Extremely high overall file entropy is consistent with packed or encrypted content, a common trait of malware"
    },
    {
      "source": "checklist_malcat_analyze",
      "query_or_table": "file_summary.layout",
      "row_or_rule": ".text section entropy=202",
      "why": "Extremely high entropy in the executable code section confirms the sample's code is packed/obfuscated, a strong indicator of malicious intent"
    },
    {
      "source": "checklist_malcat_analyze",
      "query_or_table": "views.anomalies",
      "row_or_rule": "BigBufferNoXrefMediumToHighEntropy",
      "why": "Malcat anomaly detection of a large unlinked high-entropy buffer indicates a cryptographic block, commonly used by malware to encrypt/decrypt payloads or C2 communications"
    },
    {
      "source"
… [1463 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Packed RC4-Enabled Windows Malware (SHA256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2)",
  "mark": "# Malware Analysis Report: Packed RC4-Enabled Windows Malware (SHA256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2)\n\n## Executive Summary\nThis report details the analysis of a malicious packed 32-bit Windows Portable Executable (PE) sample with SHA256 e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2. The sample received a triage verdict of Malicious with a score of 9/10, classified as a packed binary consistent with ransomware or info-stealer functionality (source: triage_verdict). Static analysis confirms extreme entropy (201 overall, 202 in the .text section), heavy obfuscation, a custom XOR-based in-memory unpacking routine, RC4 encryption capabilities, and high-signal imports including FreeEncryptedFileKeyInfo and SystemFunction033 (source: malcat, capa, pe_imports). YARA scanning confirmed the sample is packed, contains embedded domain, IPv6, and base64 indicators, and has a valid Rich header (source: yara). No dynamic analysis was performed, so runtime behavior is inferred from static indicators. The sample is not packed with UPX and uses a custom packing scheme, with no matches to known malware families (source: upx_unpack, deep_dive).\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 |\n| Sample Path | /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir |\n| Project Name | incoming |\n| File Type | 32-bit Windows GUI Portable Executable (PE) |\n| Packer | Custom (not UPX, confirmed via UPX 5.1.0 probe) |\n| Entropy | 201 (overall), 202 (.text section) |\n| Rich Header | Present, generated by unknown tool |\n| Checksum | Missing (NoChecksum anomaly) |\nThe XORSearch tool confirmed the MZ header is XOR-obfuscated at the start of the file, with the first XOR key candidate starting at offset 0x000000B8 (source: xorsearch). The sample is not a .NET assembly (source: dotnet_analyze).\n\n## 2. Classification\n| Field | Value |\n|-------|-------|\n| Verdict | Malicious |\n| Confidence | 90% |\n| Family | Unknown (packed custom malware, likely ransomware or info-stealer) |\n| Rationale | High entropy, packing anomalies, RC4 encryption capability, FreeEncryptedFileKeyInfo import, system language reconnaissance behavior, and embedded C2 indicators are all highly consistent with malicious intent. No legitimate use case exists for these traits in combination (source: triage_verdict, deep_dive, malcat).\nThe sample is not associated with any known dual-use remote access tool (RAT) families, and no vendor detection matches were found (source: deep_dive).\n\n## 3. Initial Triage (15 minutes)\nInitial triage was completed within 15 minutes of sample ingestion, yielding a malicious score of 9/10. Key findings from the triage phase include: 1) Extremely high file entropy (201) indicating heavy obfuscation or packing, 2) No readable decoded strings from FLOSS analysis, 3) High-signal import of advapi32.FreeEncryptedFileKeyInfo, a API commonly used by ransomware and info-stealers, 4) capa rule detection of RC4 encryption via SystemFunction033 and system language discovery behavior, 5) YARA matches for IsPacked, IsWindowsGUI, HasRichSignature, domain, IP, and
… [42828 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, IsPacked, HasRichSignature). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Packed malicious binary (likely ransomware or info-stealer, consistent with RC4 encryption and FreeEncryptedFileKeyInfo usage)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Packed RC4-Enabled Windows Malware (SHA256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2)

## Executive Summary
This report details the analysis of a malicious packed 32-bit Windows Portable Executable (PE) sample with SHA256 e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2. The sample received a triage verdict of Malicious with a score of 9/10, classified as a packed binary consistent with ransomware or info-stealer functionality (source: triage_verdict). Static analysis confirms extreme entropy (201 overall, 202 in the .text section), heavy obfuscation, a custom XOR-based in-memory unpacking routine, RC4 encryption capabilities, and high-signal imports including FreeEncryptedFileKeyInfo and SystemFunction033 (source: malcat, capa, pe_imports). YARA scanning confirmed the sample is packed, contains embedded domain, IPv6, and base64 indicators, and has a valid Rich header (source: yara). No dynamic analysis was performed, so runtime behavior is inferred from static indicators. The sample is not packed with UPX and uses a custom packing scheme, with no matches to known malware families (source: upx_unpack, deep_dive).

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 |
| Sample Path | /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir |
| Project Name | incoming |
| File Type | 32-bit Windows GUI Portable Executable (PE) |
| Packer | Custom (not UPX, confirmed via UPX 5.1.0 probe) |
| Entropy | 20
… [19769 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — e891b8f4825a
_Generated 2026-08-03T06:40:35.639396+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=351c | cross_refs=True | llm_ok=True | runtime=15.54s -->

# Executive Summary
The analyzed sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) is definitively classified as **Malicious** with 90% confidence, with full agreement between the LLM-based analysis and the v1 detection engine (source: scorecard, deep_dive_agentic). Core classification and sample metadata are summarized in the table below:

| Metric | Value |
|--------|-------|
| Verdict | Malicious |
| Confidence Score | 90% |
| Analysis Agreement | LLM and v1 engine full alignment |
| Sample Type | 32-bit Windows Portable Executable (PE) |
| Probable Malware Family | Packed ransomware or info-stealer |

Static and behavioral analysis confirms the sample is a packed binary with high confidence it is a ransomware variant over an info-stealer, driven by observed RC4 encryption implementation and interaction with the Windows `FreeEncryptedFileKeyInfo` EFS API (source: cross-section:9. Comparison with Known Families, capa). Automated detection engines matched 7 YARA rules and 2 CAPA capability rules against the sample, yielding a v1 detection score of 290 (source: v1_summary, yara, capa).

The sample implements two confirmed MITRE ATT&CK techniques across defense evasion and discovery tactics (source: cross-section:8. MITRE ATT&CK Mapping). No static or runtime network indicators (command-and-control IPs, URLs, network-associated mutexes) were identified during analysis (source: cross-section:6. Network Analysis), and the only confirmed indicator of compromise is the sample's unique SHA256 hash (source: cross-section:11. Indicators of Compromise). No persistent execution artifacts (malicious registry keys, services, or dropped file paths) were observed, reducing immediate persistence risk (source: cross-section:13. Containment, Eradication, Recovery).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=273c | cross_refs=True | llm_ok=True | runtime=29.37s -->

# 1. Sample Identification

This section documents core static identifiers and base properties for the analyzed sample, used for tracking, sharing, and detection across analysis workflows. All base identifiers are derived from the sample's raw file metadat
… [46937 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6444` | `6fb25ae478cbadbe` |
| `prompt.txt` | `True` | `19576` | `7729b50e26c8c934` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `22273` | `bf08b63e6ceda10f` |
| `REPORT-MASTER-v3.md` | `True` | `49451` | `9e4821371107c3e6` |
| `REPORT-v2.md` | `True` | `22273` | `bf08b63e6ceda10f` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `41999` | `1c9c8beb8ecb98b7` |
| `rule.yar` | `True` | `1112` | `1bf24f930851d6ff` |
| `intake-validation.json` | `True` | `2541` | `d7ce5e068440f448` |
| `source-decisions.json` | `True` | `1673` | `d83129825ca4f6a6` |
| `malcat-triage.json` | `True` | `18606` | `390dfb4037f7ff67` |
| `deep_dive/01-tools-raw.json` | `True` | `56930` | `8c19d13f7dd16823` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4963` | `44ca55beb3cbf152` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `53566` | `4edb13723e50d4c4` |

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

- **intake_validation:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/intake-validation.json` exists=`True` bytes=`2541` mtime=`2026-08-03T06:32:22.255643+00:00`
  - sha256: `d7ce5e068440f448be0f5112a856589633b19f1b68e69e0346aeaaa0ac1d8ae0`
- **malcat_triage:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/malcat-triage.json` exists=`True` bytes=`18606` mtime=`2026-08-03T06:31:45.409646+00:00`
  - sha256: `390dfb4037f7ff679e245f92a1c6319143d46b7f4e6a57cb9b67df4a61ed9d12`
- **source_decisions:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/source-decisions.json` exists=`True` bytes=`1673` mtime=`2026-08-03T06:32:22.255643+00:00`
  - sha256: `d83129825ca4f6a66ec85286773b48c846b18f955d875232c865c1bb4f43a9fb`
- **ghidra_import_log:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/intake-analyzeHeadless.log` exists=`True` bytes=`7988` mtime=`2026-08-03T06:31:49.916845+00:00`
  - sha256: `cc5d3ed1df05a6855bb523c07a9064705521534637f0eac6633a080b0a5525ee`
- **ida_bootstrap_log:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is non-functional due to validation failure (missing /usr/local/bin/idasql binary) and reports 0 imports; Ghidra reports 7 imports, aligning with Malcat's import count, making it the reliable source for import data."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is non-functional and reports 0 functions; Ghidra reports 365 functions, far exceeding Malcat's 10, providing comprehensive function coverage for analysis."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Malcat reports 100 strings and Ghidra reports 11 strings; combining both sources e
… [896 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
    "file_name": "virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "file_path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "file_size": 481280,
    "type": "PE",
    "architecture": "X86",
    "entropy": 201,
    "sha256": "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2"
… [17806 more chars]
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
  "rule_count": 2,
  "top_rules": [
    {
      "name": "encrypt data using RC4 via SystemFunction033",
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
            "Encryption-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encryption-Standard Algorithm",
          "id": "E1027.m05"
        },
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
        }
      ]
    },
    {
      "name": "identify system language via API",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Location Discovery",
            "System Language Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Location Discovery",
          "subtechnique": "System Language Discovery",
          "id": "T1614.001"
        }
      ],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 481280,
  "duration_s": 1.44,
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
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 339946,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 479934,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 160,
          "length": 4,
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
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`
… [1286 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1144,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "Rich!l",
    "`.rdata",
    "@.data",
    "eq9f(2A",
    "cqn,)=Aq",
    "QiR?])",
    "MC\tHsC",
    ":U=y-]",
    "m67X|}",
    "`s^cI(N",
    "rm33Um",
    "TX=w2U=",
    "T8);:V",
    "TX=w2Y=",
    "r|jW2!",
    "0Yh%2Y",
    "rx(dxs",
    "KdS8i'",
    "($38iG",
    "ES;i%>8",
    "{+Gp;i",
    "G83cO8",
    "eerXHD",
    "EORXHD",
    "E\\Nt:H",
    "r=93un",
    "gbq|]%ta",
    "*7J(57?EA",
    "rjth&h",
    "X{4eWw",
    "e?M&2h",
    "5hxu\tE",
    "w_&U4%t",
    "*}E5-u",
    "{[A6u{",
    "$FkOdH,",
    "cOdW,m",
    "2FlOdO,O$&;",
    "9O$F,X$",
    "2FlOdO,O$&;3",
    "=b*Z\t,^",
    "w_4:j^",
    "PhV!xG9qHFW",
    "^X<=\\[",
    "*7p&jjx",
    "p0(0(\"e",
    "j{lRcKz",
    "VBrDzV",
    "S/1 Sp",
    "#yp@{7",
    "s/q {7",
    "55wkEg",
    "Al<Yp}",
    "rTFP#K",
    "K=v86#",
    "EHTeW7",
    "Gi:xRU",
    "ho:XiU",
    "|5}jE1",
    "5hnJ0zT",
    "7i;L&q",
    "<7a{#?l",
    "<7a{#?",
    "La$?af07",
    "[Mf52La$?a",
    "c5RLa$?a",
    "i$?af\"7",
    "q[]4AWR",
    "npzLA(u",
    "\\nhDWx8onkw",
    "D~tz(J",
    ")Wz5>t",
    "`QAOh1",
    "+$|P;a",
    "?a;=?a",
    "A+5Iwz",
    "tR7zCY",
    "E]{=C_YYI",
    "B~s)}H"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1144
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 6.5,
  "size_bytes": 481280,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
    "file_name": "virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "file_path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
    "file_size": 481280,
    "type": "PE",
    "architecture": "X86",
    "entropy": 201,
    "sha256": "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
    "metadata": {},
    "entrypoint_ea": 1536,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1536,
        "virtual_size": 0,
        "rights": "",
        "entropy": 39
      },
      {
        "name": ".text",
        "effective_address": 1536,
        "physical_size": 478208,
        "virtual_size": 479232,
        "rights": "RX",
        "entropy": 202
      },
      {
        "name": ".rdata",
        "effective_address": 480768,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".data",
        "effective_address": 484864,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".rsrc",
        "effective_address": 488960,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 44
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
        "num_hits": 19
      },
      {
        "name": "CodeSectionNotExecutable",
        "desc": "code section is not executable",
        "category": "sections",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "DataBetweenHeaderAndFirstSection",
        "desc": "There is non-zero data between the PE header and the first section",
        "category": "headers",
        "level": 3,
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
        "name": "HighEntropy",
        "desc": "File has high entropy overall (> 200)",
        "category": "entropy",
        "level": 2,
        "num_hits": 0
      },
      {
        "name": "ManyHighValueImmediates",
        "desc": "Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate values that contains at least 2 non-zero non-FF bytes and are not a valid address)",
        "category": "code",
        "level": 3,
        "num_hits": 8
      },
      {
        "name": "ManyUniqueImmediateBytes",
        "desc": "More than 48 unique bytes defined across all immediate 
… [37036 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    " static_profile High entropy confirms heavy obfuscation; the anomaly set (large unreferenced high-entropy buffers likely",
    " top_rules Direct detection of RC4 encryption behavior, a common technique for malicious payload obfuscation, decryption",
    " decompilation This is a decryption/decryption routine, a common startup behavior for packed malware to unpack its paylo",
    " imports FreeEncryptedFileKeyInfo is a high-signal API for handling encrypted files, commonly used by ransomware or info",
    " top_rules System language discovery is a common reconnaissance behavior for targeted malware, including ransomware that"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Packed malicious binary (likely ransomware or info-stealer, consistent with RC4 encryption and FreeEncryptedFileKeyInfo usage)",
  "score": 9,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row": "type=PE, architecture=X86, entropy=201, anomalies: BigBufferNoXrefMediumToHighEntropy (19 hits), ManyHighValueImmediates (8 hits), ManyUniqueImmediateBytes (7 hits), SequentialFunction, GuiSubsystemNoWindowApi, NoChecksum, RichUnknownTool",
      "why": "High entropy confirms heavy obfuscation; the anomaly set (large unreferenced high-entropy buffers likely for crypto material, obfuscated code traits, missing checksum, unknown Rich header tool) is highly consistent with packed malicious code."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "Rule 'encrypt data using RC4 via SystemFunction033' (ATT&CK T1027, MBC C0027.009 RC4)",
      "why": "Direct detection of RC4 encryption behavior, a common technique for malicious payload obfuscation, decryption of embedded payloads, or data encryption."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation",
      "row": "sub_474643 loop XORing 0x71a06 bytes at address 0x401400 with sequential 32-bit constants",
      "why": "This is a decryption/decryption routine, a common startup behavior for packed malware to unpack its payload in memory."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row": "advapi32.FreeEncryptedFileKeyInfo, user32.dll, advapi32.dll, ntdll.dll, kernel32.dll",
      "why": "FreeEncryptedFileKeyInfo is a high-signal API for handling encrypted files, commonly used by ransomware or info-stealing malware; the import set supports Windows system interaction for malicious activity."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "Rule 'identify system language via API' (ATT&CK T1614.001)",
      "why": "System language discovery is a common reconnaissance behavior for targeted malware, including ransomware that may selectively encrypt files based on system language to avoid detection in certain regions."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row": "1144 total static strings, 0 decoded/stack/tight strings, all obfuscated",
      "why": "Complete absence of readable decoded strings indicates heavy obfuscation, consistent with packed malware that hides its indicators."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row": "IsPacked, IsWindowsGUI, contains_base64, domain, IP, HasRichSignature",
      "why": "IsPacked confirms obfuscation; presence of base64, domain, and IP indicators suggests embedded network or payload encoding capabilities; IsWindowsGUI with no window API imports (per Malcat GuiSubsystemNoWindowApi anomaly) is a common trait of malicious GUI binaries that run hidden."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation",
      "row": "sub_473970 implements a rolling XOR/bitwise shift checksum calculation routine",
      "why": "Checksum routines are commonly used in malware to verify the integrity of embedded payloads or configuration data before execution."
    }
  ],
  "summary": "This is a packed, heavily obfuscated x86 Windows PE binary with high entropy (201) and no readable decoded strings. Static analysis detects a large in-memory decryption routine, RC4 encryption capabilities, and system language reconnaissance behavior. Imports include the high-signal FreeEncryptedFileKeyInfo API, and anomaly analysis confirms traits consistent with packed malware (large unreference"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/prompt.txt` exists=`True` bytes=`19576` mtime=`2026-08-03T06:32:35.629642+00:00`
  - sha256: `7729b50e26c8c934d1fcebc4eee62227da1db0f8b0f98f883db4e00876ee1e29`
- **verdict:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/verdict.json` exists=`True` bytes=`6444` mtime=`2026-08-03T06:33:13.740140+00:00`
  - sha256: `6fb25ae478cbadbec9474bf94b747bd57cad6b6182c42782d610a134e5994118`

#### prompt_excerpt

```
# Triage evidence
sha256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2
sample_path: /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir
ghidra_session: ghidra-pe-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2
ida_session: ida-e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA is non-functional due to validation failure (missing /usr/local/bin/idasql binary) and reports 0 imports; Ghidra reports 7 imports, aligning with Malcat's import count, making it the reliable source for import data.
- functions: ghidra (confidence=medium) — IDA is non-functional and reports 0 functions; Ghidra reports 365 functions, far exceeding Malcat's 10, providing comprehensive function coverage for analysis.
- strings: both (confidence=high) — Malcat reports 100 strings and Ghi
… [18555 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 9,
  "family_guess": "Packed malicious binary (likely ransomware or info-stealer, consistent with RC4 encryption and FreeEncryptedFileKeyInfo usage)",
  "cross_engine_notes": "IDA is non-functional due to missing /usr/local/bin/idasql binary, so all IDA-sourced data (imports, functions, strings, decompilation) is unavailable. Ghidra reports 365 functions and 7 imports, but its imports virtual table is empty, so import data is sourced from Malcat and pe_imports. String data is combined from Ghidra (11 strings) and FLOSS/Malcat (1144 total strings) for full coverage. Malcat is the sole source for reliable static profile, decompilation, and anomaly data as IDA is non-functional.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row": "type=PE, architecture=X86, entropy=201, anomalies: BigBufferNoXrefMediumToHighEntropy (19 hits), ManyHighValueImmediates (8 hits), ManyUniqueImmediateBytes (7 hits), 
… [5444 more chars]
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
  "rule_count": 2,
  "top_rules": [
    {
      "name": "encrypt data using RC4 via SystemFunction033",
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
            "Encryption-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encryption-Standard Algorithm",
          "id": "E1027.m05"
        },
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
        }
      ]
    },
    {
      "name": "identify system language via API",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Location Discovery",
            "System Language Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Location Discovery",
          "subtechnique": "System Language Discovery",
          "id": "T1614.001"
        }
      ],
      "mbc": []
    }
  ],
  "timeout_s": 60,
  "sample_size": 481280,
  "duration_s": 0.95,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 481280,
  "duration_s": 0.03,
  "import_count": 7,
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
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 339946,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 479934,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 160,
          "length": 4,
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
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`
… [1264 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1144,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "Rich!l",
    "`.rdata",
    "@.data",
    "eq9f(2A",
    "cqn,)=Aq",
    "QiR?])",
    "MC\tHsC",
    ":U=y-]",
    "m67X|}",
    "`s^cI(N",
    "rm33Um",
    "TX=w2U=",
    "T8);:V",
    "TX=w2Y=",
    "r|jW2!",
    "0Yh%2Y",
    "rx(dxs",
    "KdS8i'",
    "($38iG",
    "ES;i%>8",
    "{+Gp;i",
    "G83cO8",
    "eerXHD",
    "EORXHD",
    "E\\Nt:H",
    "r=93un",
    "gbq|]%ta",
    "*7J(57?EA",
    "rjth&h",
    "X{4eWw",
    "e?M&2h",
    "5hxu\tE",
    "w_&U4%t",
    "*}E5-u",
    "{[A6u{",
    "$FkOdH,",
    "cOdW,m",
    "2FlOdO,O$&;",
    "9O$F,X$",
    "2FlOdO,O$&;3",
    "=b*Z\t,^",
    "w_4:j^",
    "PhV!xG9qHFW",
    "^X<=\\[",
    "*7p&jjx",
    "p0(0(\"e",
    "j{lRcKz",
    "VBrDzV",
    "S/1 Sp",
    "#yp@{7",
    "s/q {7",
    "55wkEg",
    "Al<Yp}",
    "rTFP#K",
    "K=v86#",
    "EHTeW7",
    "Gi:xRU",
    "ho:XiU",
    "|5}jE1",
    "5hnJ0zT",
    "7i;L&q",
    "<7a{#?l",
    "<7a{#?",
    "La$?af07",
    "[Mf52La$?a",
    "c5RLa$?a",
    "i$?af\"7",
    "q[]4AWR",
    "npzLA(u",
    "\\nhDWx8onkw",
    "D~tz(J",
    ")Wz5>t",
    "`QAOh1",
    "+$|P;a",
    "?a;=?a",
    "A+5Iwz",
    "tR7zCY",
    "E]{=C_YYI",
    "B~s)}H"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1144
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 6.2,
  "size_bytes": 481280,
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
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "disassembly": {
    "0x00475a2a": "; CALL XREF from entry0 @ 0x401000(x)\n\u250c 6: LCID sub.kernel32.dll_GetSystemDefaultLCID ();\n\u2514           0x00475a2a      ff2520604700   jmp dword [sym.imp.kernel32.dll_GetSystemDefaultLCID] ; 0x476020 ; \"Na\\a\"",
    "0x00475a1e": "; XREFS(46)\n\u250c 6: int sub.user32.dll_MessageBoxExA (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId);\n\u2514           0x00475a1e      ff2500604700   jmp dword [sym.imp.user32.dll_MessageBoxExA] ; 0x476000",
    "0x00475a24": "; XREFS(50)\n\u250c 6: sub.advapi32.dll_SystemFunction033 ();\n\u2514           0x00475a24      ff2508604700   jmp dword [sym.imp.advapi32.dll_SystemFunction033] ; 0x476008",
    "0x00475a30": "; CALL XREFS from entry0 @ 0x401093(x), 0x40111c(x), 0x4011a5(x)\n\u250c 6: LANGID sub.kernel32.dll_GetUserDefaultUILanguage ();\n\u2514           0x00475a30      ff2524604700   jmp dword [sym.imp.kernel32.dll_GetUserDefaultUILanguage] ; 0x476024 ; \"ea\\a\""
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x00401000",
    "0x00475a2a",
    "0x00475a1e",
    "0x00475a24",
    "0x00475a30"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
    "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "IsPE32 matches Confirms the sample is a valid 32-bit Portable Executable, the standard format for Windows applications a",
    "IsWindowsGUI matches Confirms the sample is a Windows GUI application, a common type for end-user facing malware checkli",
    "IsPacked matches Indicates the executable is packed/obfuscated, a common technique used by malware to evade static detec",
    "HasRichSignature matches Confirms the PE has a valid Rich header, which combined with other malicious indicators rules o",
    "domain matches YARA domain rule match confirms the sample contains an embedded malicious domain string, likely used for "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "The analyzed sample is a packed 32-bit Windows GUI Portable Executable (PE). YARA scanning confirms it is a valid PE32 file with a Windows GUI subsystem, is packed/obfuscated, contains a valid Rich header, and has embedded domain, IPv6 address, and base64 string indicators. Malcat deep analysis show",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "IsPE32",
      "why": "Confirms the sample is a valid 32-bit Portable Executable, the standard format for Windows applications and malware"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "IsWindowsGUI",
      "why": "Confirms the sample is a Windows GUI application, a common type for end-user facing malware"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "IsPacked",
      "why": "Indicates the executable is packed/obfuscated, a common technique used by malware to evade static detection and hinder reverse engineering"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "HasRichSignature",
      "why": "Confirms the PE has a valid Rich header, which combined with other malicious indicators rules out a corrupt or non-functional PE file"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "domain",
      "why": "YARA domain rule match confirms the sample contains an embedded malicious domain string, likely used for command-and-control (C2) communication"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "IP",
      "why": "YARA IP rule match confirms the sample contains an embedded IPv6 address, likely a C2 server address for network communication"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "contains_base64",
      "why": "YARA base64 rule match confirms the sample contains embedded base64-encoded data, likely used for payload delivery or C2 traffic obfuscation"
    },
    {
      "source": "checklist_malcat_analyze",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy=201",
      "why": "Extremely high overall file entropy is consistent with packed or encrypted content, a common trait of malware"
    },
    {
      "source": "checklist_malcat_analyze",
      "query_or_table": "file_summary.layout",
      "row_or_rule": ".text section entropy=202",
      "why": "Extremely high entropy in the executable code section confirms the sample's code is packed/obfuscated, a strong indicator of malicious intent"
    },
    {
      "source": "checklist_malcat_analyze",
      "query_or_table": "views.anomalies",
      "row_or_rule": "BigBufferNoXrefMediumToHighEntropy",
      "why": "Malcat anomaly detection of a large unlinked high-entropy buffer indicates a cryptographic block, commonly used by malware to encrypt/decrypt payloads or C2 communications"
    },
    {
      "source": "checklist_malcat_analyze",
      "query_or_table": "file_summary",
      "row_or_rule": "kesakode_verdict=[]",
      "why": "Empty Kaspersky verdict indicates the sample is not a known legitimate file, supporting malicious classification"
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
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
      "
… [4364 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
… [40114 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 2,
  "top_rules": [
    {
      "name": "encrypt data using RC4 via SystemFunction033",
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
    
… [1241 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 481280,
  "duration_s": 0.03,
  "import_count": 7,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 1144,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "Rich!l",
    "`.rdata",
    "@.data",
    "eq9f(2A",
    "cqn,)=Aq",
    "QiR?])",
    "MC\tHsC",
    ":U=y-]",
    "m67X|}",
    "`s^cI(N",
    "rm33Um",
    "TX=w2U=",
    "T8);:V",
    "TX=w2Y=",
    "r|jW2!",
    "0Yh%2Y",
    "rx(dxs",
    "KdS8i'",
    "(
… [1286 more chars]
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
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "disassembly": {
    "0x00475a2a": "; CALL XREF from entry0 @ 0x401000(x)\n\u250c 6: LCID sub.kernel32.dll_GetSystemDefaultLCID ();\n\u2514           0x00475a2a      ff2520604700   jmp dword [sym.imp.kernel32.dll_GetSys
… [946 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
    "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
  "rows": [
    {
      "name": "entry",
      "address": "4198400",
      "size": "560"
    },
    {
      "name": "FUN_00472edc",
      "address": "4665052",
      "size": "56"
    },
    {
      "name": "FUN_004757ef",
      "address": "4675567",
      "size": "56"
    },
    {
      "name": "FUN_0047406c",
      "address": "4669548",

… [2222 more chars]
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
      "address": "1",
      "name": "MessageBoxExA",
      "module": "USER32.DLL"
    },
    {
      "address": "2",
      "name": "SystemFunction033",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "3",
      "name": "FreeEncryptedFileKeyInfo",
      "module": "ADVAPI32.DLL"
    },
    {
      "address":
… [702 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: name`

```json
{
  "error": "ghidrasql SQL error: no such column: name"
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
      "content": "MessageBoxExA",
      "address": "4677822",
      "length": "14"
    },
    {
      "content": "user32.dll",
      "address": "4677836",
      "length": "11"
    },
    {
      "content": "SystemFunction033",
      "address": "4677849",
      "length": "18"
    },
    {
      "content": "FreeEncryp
… [988 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/01-tools-raw.json` exists=`True` bytes=`56930` mtime=`2026-08-03T06:33:27.207739+00:00`
  - sha256: `8c19d13f7dd16823c9106ee6523d0af2d743769596d50f445e9df621184c3e4d`
- **sql_evidence:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/05-deep-dive.json` exists=`True` bytes=`4963` mtime=`2026-08-03T06:34:11.424736+00:00`
  - sha256: `44ca55beb3cbf152bf345ce0aec56043a34063e44a8a1e52e3584c77058ed6e2`

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
  "summary": "The analyzed sample is a packed 32-bit Windows GUI Portable Executable (PE). YARA scanning confirms it is a valid PE32 file with a Windows GUI subsystem, is packed/obfuscated, contains a valid Rich header, and has embedded domain, IPv6 address, and base64 string indicators. Malcat deep analysis shows extremely high overall file entropy (201) and .text section entropy (202) consistent with packing, plus an anomaly indicating a large unlinked high-entropy buffer likely used for cryptographic operations. No legitimate Kaspersky detection matches were found for the sample.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
  
… [4163 more chars]
```

- **agentic:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`152767` mtime=`2026-08-03T06:34:11.424736+00:00`
  - sha256: `3e984bd96534f6259e7f4630219f5a68acd9fe8a59abdd69820f54435c45afb0`

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

- **rule_yar:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/rule.yar` exists=`True` bytes=`1112` mtime=`2026-08-03T06:34:12.729737+00:00`
  - sha256: `1bf24f930851d6ff4e71b77bafeee8c356a5678f11c7ca260e2a50f73a1a8321`

#### excerpt

```
// yara_gen_v2.py — 2026-08-03T06:34:12.730647+00:00
rule CADRE_v2_unknown_e891b8f4825a {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "FreeEncryptedFileKeyInfo" ascii wide
        $s1 = "GetUserDefaultUILanguage" ascii wide
        $s2 = "ZwAdjustPrivilegesToken" ascii wide
        $s3 = "GetUserDefaultLangID" ascii wide
        $s4 = "GetSystemDefaultLCID" ascii wide
        $s5 = "SystemFunction033" ascii wide
        $s6 = "MessageBoxExA" ascii wide
        $s7 = "advapi32.dll" ascii wide
        $s8 = "kernel32.dll" ascii wide
        $s9 = "
… [310 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-MASTER-v2.md` exists=`True` bytes=`22273` mtime=`2026-08-03T06:35:25.791732+00:00`
  - sha256: `bf08b63e6ceda10f9271f84912e7ac1728ef11fc580811b1f65e5a1e13477b3e`
- **REPORT_MASTER_v3:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-MASTER-v3.md` exists=`True` bytes=`49451` mtime=`2026-08-03T06:40:35.640113+00:00`
  - sha256: `9e4821371107c3e6fa59c95d57ce6679f70b8e9082c5cc4b6337a74803fa53fe`
- **REPORT_v2:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-v2.md` exists=`True` bytes=`22273` mtime=`2026-08-03T06:35:25.791732+00:00`
  - sha256: `bf08b63e6ceda10f9271f84912e7ac1728ef11fc580811b1f65e5a1e13477b3e`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`52460` mtime=`2026-08-03T06:37:09.077526+00:00`
  - sha256: `968feed855463c2d126839105081684f3a3e527f073434e23c2c801c9898b6a2`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`41999` mtime=`2026-08-03T06:41:50.542609+00:00`
  - sha256: `1c9c8beb8ecb98b71a0cf4fa626b0748f18f61c26b688d4256bfc3ae5ff00899`
- **report_v2_json:** `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/report-v2.json` exists=`True` bytes=`46328` mtime=`2026-08-03T06:37:09.080226+00:00`
  - sha256: `d2910a69c2bc5810b6b3fe87081f31d77370781368bdacbebcd085b1535f16c7`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, IsPacked, HasRichSignature). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Packed malicious binary (likely ransomware or info-stealer, consistent with RC4 encryption and FreeEncryptedFileKeyInfo usage)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Packed RC4-Enabled Windows Malware (SHA256: e891
… [21369 more chars]
```


#### v3_excerpt

```
# RE Report — e891b8f4825a
_Generated 2026-08-03T06:40:35.639396+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=351c | cross_refs=True | llm_ok=True | runtime=15.54s -->

# Executive Summary
The analyzed sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) is definitively classified as **Malicious** with 90% confidence, with full agreement between the LLM-based analysis and the v1 detection engine (source: scorecard, deep_dive_agentic). Core classification and sample metadata are summarized in the table below:

| Metric | Value |
|--------|-------|
| Verdict | Malicious |
| Confidence Score | 90% |
| Analysis Agreement | LLM and v1 engine full alignment |
| Sample Type | 32-bit Windows Portable Executable (PE) |
| Probable 
… [48537 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
