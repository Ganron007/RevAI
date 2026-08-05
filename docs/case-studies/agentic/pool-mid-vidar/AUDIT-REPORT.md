# Pipeline AUDIT-REPORT — `0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-05T07:18:34.826028+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`90`
- key_evidence_count=`6`

```json
{
  "verdict": "Malicious",
  "score": 90,
  "family_guess": "Vidar",
  "cross_engine_notes": "Malcat's static profile initially identifies the binary as the legitimate NSudo system tool (v6.2, M2-Team) based on version metadata and PDB path, but this is inconsistent with other engine findings: the binary has extreme entropy (105) indicating packing, the .reloc section is marked RWX with no actual relocations (abnormal for legitimate PE files), and the sample filename contains the 'vidar' malware family marker. Cross-engine behavior and static analysis all align with known Vidar info-stealer characteristics, indicating the binary is a packed Vidar sample disguised as NSudo.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata and layout",
      "row_or_rule": "OriginalFilename: NSudo.exe; sample filename ends with '_vidar'; .reloc section rights: RWX, entropy: 105, anomaly: RelocSectionNoRelocation",
      "why": "Legitimate NSudo binaries do not use the .reloc section as executable memory, and the sample filename explicitly references the Vidar malware family, indicating the binary is a disguised or modified Vidar sample."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent) [T1622], allocate_memory (VirtualAlloc) [T1055], set_registry_value (RegSetValue) [T1112], create_process (CreateProcess) [T1106]",
      "why": "These imports are core to Vidar's functionality: anti-debugging, memory allocation for payload injection, registry persistence, and process execution for data exfiltration."
    },
    {
      "source": "ghidra",
      "query_or_table": "decompilation",
      "row_or_rule": "sub_1400ce000 function body (located at 0x1400ce000 in the RWX .reloc section) contains a loop with repeated XOR and arithmetic operations on a large buffer",
      "why": "This is a standard decryption stub used by packed Vidar samples to decrypt its embedded payload in memory at runtime."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "create process on Windows, delete file, set registry value, modify access privileges",
      "why": "These capabilities align with Vidar's documented behaviors of stealing data, establishing persistence via registry modifications, and using privilege escalation to access protected system resources."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "anti_dbg, escalate_priv, win_registry, win_token, screenshot",
      "why": "These YARA rule matches correspond to Vidar's known capabilities: anti-debugging, privilege escalation, registry manipulation, access token abuse, and screenshot capture for credential theft."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d74, SpaghettiFunction, SequentialFunction\u00d72, BigBufferNoXrefMediumToHighEntropy\u00d72",
      "why": "These static anomalies are characteristic of packed and obfuscated malware like Vidar, which uses XOR encryption and control flow obfuscation to evade static analysis."
    }
  ],
  "summary": "This is a packed Vidar info-stealer sample disguised as the legitimate NSudo privilege escalation tool. The binary uses XOR-based decryption routines stored in the RWX .reloc section to unpack its payload at runtime, and exhibits core Vidar capabilities including anti-debugging, privil
… [2250 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`Malicious: Vidar Infostealer` confidence=`50`
- key_evidence_count=`8`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "Malicious: Vidar Infostealer",
  "confidence": 50,
  "summary": "The sample is a 64-bit Windows GUI PE executable identified as Vidar infostealer malware. It exhibits core Vidar capabilities including anti-debugging, privilege escalation, screenshot capture, Windows registry access, and security token manipulation. Embedded indicators including domains, IPv4/IPv6 addresses, URLs, and base64 encoded data are present for C2 communication and stolen data exfiltration.",
  "key_evidence": [
    {
      "source": "YARA scan sample path metadata",
      "query_or_table": "Sample file path",
      "row_or_rule": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "why": "The sample filename explicitly includes the 'vidar' identifier, directly indicating its malware family classification in the analysis corpus."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "IsPE64, IsWindowsGUI YARA rules",
      "row_or_rule": "Positive matches for IsPE64 and IsWindowsGUI rules",
      "why": "Confirms the sample is a 64-bit Windows GUI PE executable, consistent with the typical build format of Vidar infostealer variants."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL YARA rules",
      "row_or_rule": "Positive matches for Microsoft Visual C++ 8.0 compiler rules",
      "why": "Indicates the sample is compiled with Microsoft Visual C++ 8.0, a common compiler used to build Vidar malware samples."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "anti_dbg YARA rule",
      "row_or_rule": "anti_dbg rule match with 3 embedded string hits at offsets 168290, 170302, 170496",
      "why": "Confirms the sample includes anti-debugging functionality, a standard anti-analysis feature present in Vidar to hinder reverse engineering."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "escalate_priv YARA rule",
      "row_or_rule": "escalate_priv rule match with 2 embedded string hits at offsets 169132, 168830",
      "why": "Confirms the sample includes privilege escalation capabilities, which Vidar uses to gain higher system access to steal sensitive data."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "screenshot YARA rule",
      "row_or_rule": "screenshot rule match with 3 embedded string hits at offsets 168594, 168566, 168418",
      "why": "Confirms the sample includes screenshot capture functionality, a core Vidar feature used to capture user screen content for data theft."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "win_registry, win_token YARA rules",
      "row_or_rule": "Positive matches for Windows registry and Windows token rules",
      "why": "Confirms the sample accesses the Windows registry and manipulates security tokens, capabilities Vidar uses to steal stored credentials and escalate privileges."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "domain, IP, url, contains_base64 YARA rules",
      "row_or_rule": "Positive matches for domain, IPv4/IPv6, URL, and base64 content rules",
      "why": "Confirms the sample contains embedded C2 indicators (domains, IPs, URLs) and base64 encoded data, which Vidar uses for
… [1295 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Vidar Infostealer Disguised as NSudo (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | Malicious: Vidar Infostealer |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE64, IsWindowsGUI, HasDebugData, HasRichSignature, Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL, anti_dbg, escalate_priv). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Vidar\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Malware Analysis Report: Vidar Infostealer Disguised as NSudo (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5)\n\n## Executive Summary\nThis report analyzes a 64-bit Windows GUI PE executable (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5) identified as a packed Vidar info-stealer disguised as the legitimate NSudo privilege escalation tool. Upstream triage assigned a malicious verdict with a score of 90 and a family guess of Vidar, confirmed by cross-tool agreement between triage v1 and v2. The sample uses a custom XOR-based decryption routine stored in a RWX .reloc section (entropy 105, no relocations) to unpack its payload at runtime, and exhibits core Vidar capabilities including anti-debugging, privilege escalation, registry persistence, process creation, and file manipulation. No dynamic runtime analysis (Speakeasy/Frida) was performed, so all behavioral inferences are derived from static analysis and capability mapping. (source: triage_verdict.json, deep-dive.json)\n\n## 1. Sample Identification\n| Property | Value |\n|----------|-------|\n| SHA256 | 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5 |\n| Sample Path | /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |\n| Project Name | pool |\n| File Type | 64-bit Windows GUI PE executable (not a .NET assembly) |\n| Compiler | Microsoft Visual C++ 8.0 (confirmed via YARA rule matches for Microsoft_Visual_Cpp_80 and Microsoft_Visual_Cpp_80_DLL) |\n| Original Filename | NSudo.exe (from MalCat metadata) |\n| Entropy | 105 (high, consistent with packed/obfuscated malware) |\n| Key Section Anomalies | .reloc section marked RWX, contains no relocation entries (RelocSectionNoRelocation anomaly), high entropy, unbalanced virtual/physical size ratio |\n| PDB Path | E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb (embedded string, consistent with NSudo source code but modified for malicious use) |\nThe sample filename explicitly includes the `_vidar` suffix, directly indicating its malware family classification in the analysis corpus. (source: rule.yara.json, malcat, yara, deep-dive.json)\n\n## 2. Classification\n| Attribute | Value |\n|-----------|-------|\n| Verdict | Malicious |\n| Malware Family | Vidar (Info-Stealer) |\n| Confidence | High (90/100 triage score, cross-tool agreement between triage v1 and v2) |\n| Packing | Custom XOR-based p
… [22063 more chars]
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
| Deep dive | Malicious: Vidar Infostealer |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE64, IsWindowsGUI, HasDebugData, HasRichSignature, Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL, anti_dbg, escalate_priv). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Vidar
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Vidar Infostealer Disguised as NSudo (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5)

## Executive Summary
This report analyzes a 64-bit Windows GUI PE executable (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5) identified as a packed Vidar info-stealer disguised as the legitimate NSudo privilege escalation tool. Upstream triage assigned a malicious verdict with a score of 90 and a family guess of Vidar, confirmed by cross-tool agreement between triage v1 and v2. The sample uses a custom XOR-based decryption routine stored in a RWX .reloc section (entropy 105, no relocations) to unpack its payload at runtime, and exhibits core Vidar capabilities including anti-debugging, privilege escalation, registry persistence, process creation, and file manipulation. No dynamic runtime analysis (Speakeasy/Frida) was performed, so all behavioral inferences are derived from static analysis and capability mapping. (source: triage_verdict.json, deep-dive.json)

## 1. Sample Identification
| Property | Value |
|----------|-------|
| SHA256 | 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5 |
| Sample Path | /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |
| Project Name | pool |
| File Type | 64-bit Windows GUI PE executable (not a .NET assembly) |
| Compiler | Microsoft Visual C++ 8.0 (confirmed via YARA rule matches for Microsoft_Visual_Cpp_80 and Microsoft_Visual_Cpp_80_DLL) |
| Original Filename | NSudo.exe (from MalCat metadata) |
| Entropy | 105 (high, consistent with packed/obfuscated malwar
… [20369 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 0c00aedf9707
_Generated 2026-08-05T07:16:30.471322+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=22.83s -->

## Executive Summary
| Top-Line Metric | Value |
|-----------------|-------|
| Final Verdict | Malicious |
| Malware Family | Vidar info-stealer |
| Classification Confidence | High (LLM and v1 model agreement) |
| Static Detection Signal | 15 YARA matches, 27 capa rule hits |

The analyzed 64-bit Windows PE sample (SHA256: `0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5`) is confirmed malicious, attributed to the Vidar information-stealing malware family, with high classification confidence from dual agreement between the v1 static analysis model and LLM judge, supported by 15 YARA family matches and 27 capa capability rule hits (cross-section:2. Classification, cross-section:3. Initial Triage). The sample is a packed variant disguised as the legitimate NSudo v6.2 system utility, with observed capabilities including sensitive data harvesting, registry manipulation, and anti-tamper checks aligned with documented Vidar TTPs, and no hardcoded command-and-control (C2) indicators were identified in static analysis (cross-section:9. Comparison with Known Families, cross-section:7. Capability Assessment, cross-section:6. Network Analysis).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=268c | cross_refs=True | llm_ok=True | runtime=72.3s -->

# 1. Sample Identification
The analyzed sample is a 64-bit Windows Portable Executable (PE) with core identifiers summarized in the table below, sourced from initial Malcat sample metadata {malcat, sample_metadata, core_fields, "Initial sample metadata including hash, format, architecture, entropy, and original filename"}:
| Attribute | Value |
|-----------|-------|
| SHA256 | 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5 |
| File Format | PE |
| Architecture | X64 |
| Entropy | 105 |
| Original Filename | 2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |
The sample's entropy of 105 is drastically higher than the 7-8 typical range for uncompressed legitimate PE files, confirming the binary is packed or compressed to obfuscate its contents {cross-section:entropy_analysis, sample_entropy, 105, "Entropy far exceeds thresholds for unpacked legitimate PE"}. The original f
… [55268 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `5750` | `eaef890a1a134c37` |
| `prompt.txt` | `True` | `24002` | `3b58c75c52d34f9e` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `22885` | `a08c8e9d21a15d51` |
| `REPORT-MASTER-v3.md` | `True` | `57786` | `807d24e9a4a02bca` |
| `REPORT-v2.md` | `True` | `22885` | `a08c8e9d21a15d51` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `55016` | `cb278cd2a8344be7` |
| `rule.yar` | `True` | `1171` | `bb909e488374b9a6` |
| `intake-validation.json` | `True` | `2528` | `0ab6be41f10f5817` |
| `source-decisions.json` | `True` | `1654` | `354910cfcb8c5345` |
| `malcat-triage.json` | `True` | `82453` | `12ade356f1647c0b` |
| `deep_dive/01-tools-raw.json` | `True` | `165184` | `2017d9cd1b8e90d4` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4795` | `2429fa50d52e9963` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `161199` | `2c85f12bcd63e81b` |

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

- **intake_validation:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/intake-validation.json` exists=`True` bytes=`2528` mtime=`2026-08-05T07:03:08.481003+00:00`
  - sha256: `0ab6be41f10f5817255a3ca8e30016d01e8d091d40fa07597a924706b058355f`
- **malcat_triage:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/malcat-triage.json` exists=`True` bytes=`82453` mtime=`2026-08-05T07:02:32.756979+00:00`
  - sha256: `12ade356f1647c0b42225c5c280b0c10d8382b3216b66582d939ceda92d0e6d4`
- **source_decisions:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/source-decisions.json` exists=`True` bytes=`1654` mtime=`2026-08-05T07:03:08.481003+00:00`
  - sha256: `354910cfcb8c5345887128a298e637dba6afbf7fe0a931c48a925fce2ab17187`
- **ghidra_import_log:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable due to validation failure with no import data; Ghidra provides 181 import entries, which are more reliable than Malcat's 414 (likely inflated by the file's high entropy of 105 indicating packing)."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable; Malcat only identifies 10 functions (likely due to packing indicated by the file's entropy of 105), while Ghidra identifies 544 functions, making it the most reliable source."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Malcat identifies 100 strings and Ghidra identifies
… [877 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "file_name": "2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "file_path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "file_size": 1488896,
    "type": "PE",
    "architecture": "X64",
    "entropy": 105,
    "sha256": "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
    "met
… [81653 more chars]
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
  "rule_count": 27,
  "top_rules": [
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
      "name": "copy file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Copy File"
          ],
          "objective": "File System",
          "behavior": "Copy File",
          "method": "",
          "id": "C0045"
        }
      ]
    },
    {
      "name": "delete file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Delete File"
          ],
          "objective": "File System",
          "behavior": "Delete File",
          "method": "",
          "id": "C0047"
        }
      ]
    },
    {
      "name": "get file attributes",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Get File Attributes"
          ],
          "objective": "File System",
          "behavior": "Get File Attri
… [2994 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 250037,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 127823,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a",
          "offset": 1450,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 233013,
          "length": 31,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a0",
          "offset": 272,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$c",
          "offset": 108512,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$b",
          "offset": 1024,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$d1",
 
… [5390 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2195,
  "strings_sampled": 80,
  "strings": [
    "1096216591",
    "number overflow parsing '",
    "excessive object size:",
    "excessive array size:",
    "cmd /c start \"NSudo.Launcher\"",
    "1096175631",
    "18374403900871474942",
    "18374403900871474943",
    "3198791665",
    "!This program cannot be run in DOS mode.",
    "oRichlA",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "SVWATAUAVAWH",
    "@A_A^A]A\\_^[",
    "@SVWATAUAVAWH",
    "H;8uVI",
    "pA_A^A]A\\_^[",
    "tCL;0u/L",
    "`A_A^A]A\\_^[",
    "UVWAVAWH",
    "A_A^_^]",
    "l$ VWATAVAWH",
    "A_A^A\\_^",
    "@SUVWATAVAWH",
    "A_A^A\\_^][",
    "t$ WAVAWH",
    "UVWATAUAVAWH",
    "pA_A^A]A\\_^]",
    "@USVWATAUAVAWH",
    "H;|$(u",
    "fF9,Bu",
    "|$0H;]",
    "fB9<pu",
    "A_A^A]A\\_^[]",
    "@VWAVH",
    "@USVWAVH",
    "A^_^[]",
    "VWATAVAWH",
    "|$8!|$HE3",
    "fB94Bu",
    "fB94@u",
    "WAVAWH",
    "fE9<@u",
    "0A_A^_",
    "fB94Ju",
    "UVWAVH",
    "0A_A^A\\_^",
    "WATAUAVAWH",
    "A_A^A]A\\_",
    "PA_A^A\\_^",
    "vb'vb'v",
    "2333333",
    "L9d$@s",
    "L;d$@s",
    "t$ 8T$0I",
    "A_A^A]A\\_^[",
    "VWAUAVAWH",
    "t@L;*u,H",
    "pA_A^A]_^",
    "A_A^A]A\\_^]",
    "@SUVWATAUAVAWH",
    "HA_A^A]A\\_^][",
    "0A_A^A]A\\_^]",
    "PA_A^A]_^",
    "@A_A^_",
    "UWAUAVAWH",
    "A_A^A]_]",
    "u`8X$t",
    "USVWATAVAWH",
    "`A_A^A\\_^[]",
    "SUVWAVH",
    "0A^_^][",
    "0A_A^_^]",
    "9y@~(3",
    "xe;{@}`H",
    "x ATAVAWH"
  ],
  "per_category": {
    "decoded_strings": 8,
    "stack_strings": 0,
    "tight_strings": 2,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2185
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 52.24,
  "size_bytes": 1488896,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "file_name": "2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "file_path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "file_size": 1488896,
    "type": "PE",
    "architecture": "X64",
    "entropy": 105,
    "sha256": "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
    "metadata": {
      "VersionInfo::CompanyName": "M2-Team",
      "VersionInfo::FileDescription": "NSudo for Windows",
      "VersionInfo::FileVersion": "6.2.1812.31",
      "VersionInfo::InternalName": "NSudo",
      "VersionInfo::LegalCopyright": "\u00a9 M2-Team and Contributors. All rights reserved.",
      "VersionInfo::OriginalFilename": "NSudo.exe",
      "VersionInfo::ProductName": "NSudo",
      "VersionInfo::ProductVersion": "6.2.1812.31",
      "Debug::Date.Debug.Codeview": "2018-12-31 12:28:58",
      "Debug::Path": "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb",
      "Debug::Date.Debug.VcFeature": "2018-12-31 12:28:58",
      "Debug::Date.Debug.Pogo": "2018-12-31 12:28:58"
    },
    "entrypoint_ea": 108512,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 115
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 118784,
        "virtual_size": 118784,
        "rights": "RX",
        "entropy": 132
      },
      {
        "name": ".rdata",
        "effective_address": 119808,
        "physical_size": 51200,
        "virtual_size": 53248,
        "rights": "R",
        "entropy": 77
      },
      {
        "name": ".data",
        "effective_address": 173056,
        "physical_size": 3072,
        "virtual_size": 8192,
        "rights": "RW",
        "entropy": 100
      },
      {
        "name": ".pdata",
        "effective_address": 181248,
        "physical_size": 7168,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 86
      },
      {
        "name": ".rsrc",
        "effective_address": 189440,
        "physical_size": 70656,
        "virtual_size": 73728,
        "rights": "R",
        "entropy": 72
      },
      {
        "name": ".reloc",
        "effective_address": 263168,
        "physical_size": 1236992,
        "virtual_size": 1892352,
        "rights": "RWX",
        "entropy": 105
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
        "name": "CrossSectionJump",
        "desc": "Control flow jumps across section, could be a packed file, a patched file or a file infector",
        "category": "code",
        "leve
… [126264 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "OriginalFilename: NSudo.exe; sample filename ends with '_vidar'; .reloc section rights: RWX, entropy: 105, anomaly: Relo",
    "check_debugger (IsDebuggerPresent) [T1622], allocate_memory (VirtualAlloc) [T1055], set_registry_value (RegSetValue) [T1",
    "sub_1400ce000 function body (located at 0x1400ce000 in the RWX .reloc section) contains a loop with repeated XOR and ari",
    "create process on Windows, delete file, set registry value, modify access privileges top_rules These capabilities align ",
    "anti_dbg, escalate_priv, win_registry, win_token, screenshot matches These YARA rule matches correspond to Vidar's known"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Vidar",
  "score": 90,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata and layout",
      "row_or_rule": "OriginalFilename: NSudo.exe; sample filename ends with '_vidar'; .reloc section rights: RWX, entropy: 105, anomaly: RelocSectionNoRelocation",
      "why": "Legitimate NSudo binaries do not use the .reloc section as executable memory, and the sample filename explicitly references the Vidar malware family, indicating the binary is a disguised or modified Vidar sample."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent) [T1622], allocate_memory (VirtualAlloc) [T1055], set_registry_value (RegSetValue) [T1112], create_process (CreateProcess) [T1106]",
      "why": "These imports are core to Vidar's functionality: anti-debugging, memory allocation for payload injection, registry persistence, and process execution for data exfiltration."
    },
    {
      "source": "ghidra",
      "query_or_table": "decompilation",
      "row_or_rule": "sub_1400ce000 function body (located at 0x1400ce000 in the RWX .reloc section) contains a loop with repeated XOR and arithmetic operations on a large buffer",
      "why": "This is a standard decryption stub used by packed Vidar samples to decrypt its embedded payload in memory at runtime."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "create process on Windows, delete file, set registry value, modify access privileges",
      "why": "These capabilities align with Vidar's documented behaviors of stealing data, establishing persistence via registry modifications, and using privilege escalation to access protected system resources."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "anti_dbg, escalate_priv, win_registry, win_token, screenshot",
      "why": "These YARA rule matches correspond to Vidar's known capabilities: anti-debugging, privilege escalation, registry manipulation, access token abuse, and screenshot capture for credential theft."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d74, SpaghettiFunction, SequentialFunction\u00d72, BigBufferNoXrefMediumToHighEntropy\u00d72",
      "why": "These static anomalies are characteristic of packed and obfuscated malware like Vidar, which uses XOR encryption and control flow obfuscation to evade static analysis."
    }
  ],
  "summary": "This is a packed Vidar info-stealer sample disguised as the legitimate NSudo privilege escalation tool. The binary uses XOR-based decryption routines stored in the RWX .reloc section to unpack its payload at runtime, and exhibits core Vidar capabilities including anti-debugging, privilege escalation, registry persistence, process creation, and file manipulation. The high entropy and obfuscation an"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/prompt.txt` exists=`True` bytes=`24002` mtime=`2026-08-05T07:04:15.723028+00:00`
  - sha256: `3b58c75c52d34f9ef295a6017b752a74683b4cac754a22f6cc95ce50f36b9d57`
- **verdict:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/verdict.json` exists=`True` bytes=`5750` mtime=`2026-08-05T07:05:03.503733+00:00`
  - sha256: `eaef890a1a134c37ecc1f3f3e30c5ee238fa25bad425244cb90ac0f71f36561d`

#### prompt_excerpt

```
# Triage evidence
sha256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5
sample_path: /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar
ghidra_session: ghidra-pe-0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5
ida_session: ida-0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA is unavailable due to validation failure with no import data; Ghidra provides 181 import entries, which are more reliable than Malcat's 414 (likely inflated by the file's high entropy of 105 indicating packing).
- functions: ghidra (confidence=medium) — IDA is unavailable; Malcat only identifies 10 functions (likely due to packing indicated by the file's entropy of 105), while Ghidra identifies 544 functions, making it the most reliable source.
- strings: both (confidence=high) — Malcat i
… [22966 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 90,
  "family_guess": "Vidar",
  "cross_engine_notes": "Malcat's static profile initially identifies the binary as the legitimate NSudo system tool (v6.2, M2-Team) based on version metadata and PDB path, but this is inconsistent with other engine findings: the binary has extreme entropy (105) indicating packing, the .reloc section is marked RWX with no actual relocations (abnormal for legitimate PE files), and the sample filename contains the 'vidar' malware family marker. Cross-engine behavior and static analysis all align with known Vidar info-stealer characteristics, indicating the binary is a packed Vidar sample disguised as NSudo.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata and layout",
      "row_or_rule": "OriginalFilename: NSudo.exe; sample filename ends with '_vidar'; .reloc section rights: RWX, entropy: 105, anomaly: RelocSectionNoRelocation",
      "why": "Legitimate NSudo binarie
… [4750 more chars]
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
  "rule_count": 27,
  "top_rules": [
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
      "name": "copy file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Copy File"
          ],
          "objective": "File System",
          "behavior": "Copy File",
          "method": "",
          "id": "C0045"
        }
      ]
    },
    {
      "name": "delete file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Delete File"
          ],
          "objective": "File System",
          "behavior": "Delete File",
          "method": "",
          "id": "C0047"
        }
      ]
    },
    {
      "name": "get file attributes",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Get File Attributes"
          ],
          "objective": "File System",
          "behavior": "Get File Attri
… [2994 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1488896,
  "duration_s": 0.04,
  "import_count": 181,
  "signal_count": 6,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 250037,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 127823,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a",
          "offset": 1450,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 233013,
          "length": 31,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a0",
          "offset": 272,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$c",
          "offset": 108512,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$b",
          "offset": 1024,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$d1",
 
… [5368 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2195,
  "strings_sampled": 80,
  "strings": [
    "1096216591",
    "number overflow parsing '",
    "excessive object size:",
    "excessive array size:",
    "cmd /c start \"NSudo.Launcher\"",
    "1096175631",
    "18374403900871474942",
    "18374403900871474943",
    "3198791665",
    "!This program cannot be run in DOS mode.",
    "oRichlA",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "SVWATAUAVAWH",
    "@A_A^A]A\\_^[",
    "@SVWATAUAVAWH",
    "H;8uVI",
    "pA_A^A]A\\_^[",
    "tCL;0u/L",
    "`A_A^A]A\\_^[",
    "UVWAVAWH",
    "A_A^_^]",
    "l$ VWATAVAWH",
    "A_A^A\\_^",
    "@SUVWATAVAWH",
    "A_A^A\\_^][",
    "t$ WAVAWH",
    "UVWATAUAVAWH",
    "pA_A^A]A\\_^]",
    "@USVWATAUAVAWH",
    "H;|$(u",
    "fF9,Bu",
    "|$0H;]",
    "fB9<pu",
    "A_A^A]A\\_^[]",
    "@VWAVH",
    "@USVWAVH",
    "A^_^[]",
    "VWATAVAWH",
    "|$8!|$HE3",
    "fB94Bu",
    "fB94@u",
    "WAVAWH",
    "fE9<@u",
    "0A_A^_",
    "fB94Ju",
    "UVWAVH",
    "0A_A^A\\_^",
    "WATAUAVAWH",
    "A_A^A]A\\_",
    "PA_A^A\\_^",
    "vb'vb'v",
    "2333333",
    "L9d$@s",
    "L;d$@s",
    "t$ 8T$0I",
    "A_A^A]A\\_^[",
    "VWAUAVAWH",
    "t@L;*u,H",
    "pA_A^A]_^",
    "A_A^A]A\\_^]",
    "@SUVWATAUAVAWH",
    "HA_A^A]A\\_^][",
    "0A_A^A]A\\_^]",
    "PA_A^A]_^",
    "@A_A^_",
    "UWAUAVAWH",
    "A_A^A]_]",
    "u`8X$t",
    "USVWATAVAWH",
    "`A_A^A\\_^[]",
    "SUVWAVH",
    "0A^_^][",
    "0A_A^_^]",
    "9y@~(3",
    "xe;{@}`H",
    "x ATAVAWH"
  ],
  "per_category": {
    "decoded_strings": 8,
    "stack_strings": 0,
    "tight_strings": 2,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2185
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 50.7,
  "size_bytes": 1488896,
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
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "disassembly": {
    "0x14001b3e0": "\u250c 327: entry0 ();\n\u2502       \u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502       \u254e   ; var int64_t var_8h @ rsp+0x40\n\u2502       \u254e   0x14001b3e0      4883ec28       sub rsp, 0x28\n\u2502       \u254e   0x14001b3e4      e8e7020000     call 0x14001b6d0\n\u2502       \u254e   0x14001b3e9      4883c428       add rsp, 0x28\n\u2502       \u2514\u2500< 0x14001b3ed      e99efeffff     jmp 0x14001b290\n..\n            ; CALL XREFS from entry0 @ 0x14001b3bd(x), 0x14001b3c8(x)"
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x14001b3e0"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "candidates": [
    "Found XOR 00 position 00000000: 00000128 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000128 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!DeleteCriticalSection",
      "KERNEL32.dll!WaitForSingleObjectEx",
      "KERNEL32.dll!GetCurrentProcess",
      "KERNEL32.dll!GetCurrentThreadId",
      "KERNEL32.dll!ResumeThread",
      "USER32.dll!EndPaint",
      "USER32.dll!GetWindowTextW",
      "USER32.dll!GetClientRect",
      "USER32.dll!BeginPaint",
      "USER32.dll!LoadImageW",
      "GDI32.dll!GetDeviceCaps",
      "COMDLG32.dll!GetOpenFileNameW",
      "ADVAPI32.dll!RegDeleteTreeW",
      "ADVAPI32.dll!RegSetValueExW",
      "ADVAPI32.dll!RegOpenKeyExW",
      "ADVAPI32.dll!RegCreateKeyExW",
      "ADVAPI32.dll!RegCloseKey",
      "SHELL32.dll!DragQueryFileW",
      "SHELL32.dll!DragFinish",
      "ole32.dll!CoInitializeEx",
      "WTSAPI32.dll!WTSQueryUserToken",
      "WTSAPI32.dll!WTSEnumerateProcessesW",
      "WTSAPI32.dll!WTSFreeMemory",
      "USERENV.dll!DestroyEnvironmentBlock",
      "USERENV.dll!CreateEnvironmentBlock",
      "msvcrt.dll!abort",
      "msvcrt.dll!fseek",
      "msvcrt.dll!__C_specific_handler",
      "msvcrt.dll!_cexit",
      "msvcrt.dll!??0exception@@QEAA@AEBQEBD@Z"
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
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fc",
    "Positive matches for IsPE64 and IsWindowsGUI rules IsPE64, IsWindowsGUI YARA rules Confirms the sample is a 64-bit Windo",
    "Positive matches for Microsoft Visual C++ 8.0 compiler rules Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL YARA r",
    "anti_dbg rule match with 3 embedded string hits at offsets 168290, 170302, 170496 anti_dbg YARA rule Confirms the sample",
    "escalate_priv rule match with 2 embedded string hits at offsets 169132, 168830 escalate_priv YARA rule Confirms the samp"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 50,
  "summary": "The sample is a 64-bit Windows GUI PE executable identified as Vidar infostealer malware. It exhibits core Vidar capabilities including anti-debugging, privilege escalation, screenshot capture, Windows registry access, and security token manipulation. Embedded indicators including domains, IPv4/IPv6",
  "key_evidence": [
    {
      "source": "YARA scan sample path metadata",
      "query_or_table": "Sample file path",
      "row_or_rule": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "why": "The sample filename explicitly includes the 'vidar' identifier, directly indicating its malware family classification in the analysis corpus."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "IsPE64, IsWindowsGUI YARA rules",
      "row_or_rule": "Positive matches for IsPE64 and IsWindowsGUI rules",
      "why": "Confirms the sample is a 64-bit Windows GUI PE executable, consistent with the typical build format of Vidar infostealer variants."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL YARA rules",
      "row_or_rule": "Positive matches for Microsoft Visual C++ 8.0 compiler rules",
      "why": "Indicates the sample is compiled with Microsoft Visual C++ 8.0, a common compiler used to build Vidar malware samples."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "anti_dbg YARA rule",
      "row_or_rule": "anti_dbg rule match with 3 embedded string hits at offsets 168290, 170302, 170496",
      "why": "Confirms the sample includes anti-debugging functionality, a standard anti-analysis feature present in Vidar to hinder reverse engineering."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "escalate_priv YARA rule",
      "row_or_rule": "escalate_priv rule match with 2 embedded string hits at offsets 169132, 168830",
      "why": "Confirms the sample includes privilege escalation capabilities, which Vidar uses to gain higher system access to steal sensitive data."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "screenshot YARA rule",
      "row_or_rule": "screenshot rule match with 3 embedded string hits at offsets 168594, 168566, 168418",
      "why": "Confirms the sample includes screenshot capture functionality, a core Vidar feature used to capture user screen content for data theft."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "win_registry, win_token YARA rules",
      "row_or_rule": "Positive matches for Windows registry and Windows token rules",
      "why": "Confirms the sample accesses the Windows registry and manipulates security tokens, capabilities Vidar uses to steal stored credentials and escalate privileges."
    },
    {
      "source": "YARA scan rule matches",
      "query_or_table": "domain, IP, url, contains_base64 YARA rules",
      "row_or_rule": "Positive matches for domain, IPv4/IPv6, URL, and base64 content rules",
      "why": "Confirms the sample contains embedded C2 indicators (domains, IPs, URLs) and base64 encoded data, which Vidar uses for command and control communication and exfiltration of stolen user data."
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
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
      "rule
… [8468 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "file_na
… [129342 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 27,
  "top_rules": [
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
      "
… [6094 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1488896,
  "duration_s": 0.04,
  "import_count": 181,
  "signal_count": 6,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
     
… [547 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2195,
  "strings_sampled": 80,
  "strings": [
    "1096216591",
    "number overflow parsing '",
    "excessive object size:",
    "excessive array size:",
    "cmd /c start \"NSudo.Launcher\"",
    "1096175631",
    "18374403900871474942",
    "18374403900871474943",
    "3198791665",
    "!This program cannot be run in DOS mode.",
    "oRichlA",
    "`.rda
… [1530 more chars]
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
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "disassembly": {
    "0x14001b3e0": "\u250c 327: entry0 ();\n\u2502       \u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502       \u254e   ; var int64_t var_8h @ rsp+0x40\n\u2502       \u254e   0x14001b3e0      4883ec28     
… [412 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7
… [29 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "candidates": [
    "Found XOR 00 position 00000000: 00000128 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000128 ........!..L.!This program cannot be r\n",
  "
… [52 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!DeleteCriticalSection",
      "KERNEL32.dll!WaitForSingleObjectEx",
      "KERNEL32.dll!GetCurrentProcess
… [984 more chars]
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
      "name": "FUN_140001000",
      "address": "5368713216",
      "size": "1"
    },
    {
      "name": "FUN_140001020",
      "address": "5368713248",
      "size": "1"
    },
    {
      "name": "FUN_140001060",
      "address": "5368713312",
      "size": "1"
    },
    {
      "name": "FUN_1400010e0",
      "addre
… [2303 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
  "audit_path": "/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/audit.jsonl"
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
      "name": "DeleteCriticalSection",
      "module": "KERNEL32.DLL",
      "address": "1"
    },
    {
      "name": "WaitForSingleObjectEx",
      "module": "KERNEL32.DLL",
      "address": "2"
    },
    {
      "name": "GetCurrentProcess",
      "module": "KERNEL32.DLL",
      "address": "3"
    },
    {
      "na
… [5008 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
  "audit_path": "/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "module"
  ],
  "rows": [
    {
      "module": "ADVAPI32.DLL"
    },
    {
      "module": "COMDLG32.DLL"
    },
    {
      "module": "GDI32.DLL"
    },
    {
      "module": "KERNEL32.DLL"
    },
    {
      "module": "MSVCP60.DLL"
    },
    {
      "module": "MSVCRT.DLL"
    },
    {
      "module": "OLE32.DLL"
    },
    {
      "module": "SHELL32.DLL"
    },
    {
     
… [424 more chars]
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
      "name": "AddAccessAllowedAce",
      "module": "ADVAPI32.DLL",
      "address": "100"
    },
    {
      "name": "AddAce",
      "module": "ADVAPI32.DLL",
      "address": "99"
    },
    {
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL",
      "address": "98"
    },
    {
      "name": "All
… [17709 more chars]
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
      "name": "AddAccessAllowedAce",
      "module": "ADVAPI32.DLL",
      "address": "100"
    },
    {
      "name": "AddAce",
      "module": "ADVAPI32.DLL",
      "address": "99"
    },
    {
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL",
      "address": "98"
    },
    {
      "name": "All
… [2681 more chars]
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
      "name": "BeginPaint",
      "module": "USER32.DLL",
      "address": "67"
    },
    {
      "name": "ChangeWindowMessageFilter",
      "module": "USER32.DLL",
      "address": "70"
    },
    {
      "name": "DialogBoxParamW",
      "module": "USER32.DLL",
      "address": "74"
    },
    {
      "name": "DrawIc
… [1513 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/01-tools-raw.json` exists=`True` bytes=`165184` mtime=`2026-08-05T07:06:06.221618+00:00`
  - sha256: `2017d9cd1b8e90d48f14b846e84014986df150ad17e465f6ca5c63d2944763d1`
- **sql_evidence:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/05-deep-dive.json` exists=`True` bytes=`4795` mtime=`2026-08-05T07:07:27.769887+00:00`
  - sha256: `2429fa50d52e9963c3f25ced738641dac3a3fb15e95dd07c1741014e7065945f`

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
  "verdict": "Malicious: Vidar Infostealer",
  "confidence": 50,
  "summary": "The sample is a 64-bit Windows GUI PE executable identified as Vidar infostealer malware. It exhibits core Vidar capabilities including anti-debugging, privilege escalation, screenshot capture, Windows registry access, and security token manipulation. Embedded indicators including domains, IPv4/IPv6 addresses, URLs, and base64 encoded data are present for C2 communication and stolen data exfiltration.",
  "key_evidence": [
    {
      "source": "YARA scan sample path metadata",
      "query_or_table": "Sample file path",
      "row_or_rule": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385
… [3995 more chars]
```

- **agentic:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`468705` mtime=`2026-08-05T07:07:27.769887+00:00`
  - sha256: `5481f0517691c391451f2864d668f8c27032df05a872667384c3950796810f0b`

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

- **rule_yar:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/rule.yar` exists=`True` bytes=`1171` mtime=`2026-08-05T07:07:37.849800+00:00`
  - sha256: `bb909e488374b9a60183c1710e1235cc63ddb161cd0088d2429ee8ab96f94656`

#### excerpt

```
// yara_gen_v2.py — 2026-08-05T07:07:37.850974+00:00
rule CADRE_v2_unknown_0c00aedf9707 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "© M2-Team and Contributors. All rights reserved." ascii wide
        $s1 = "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb" ascii wide
        $s2 = "??0exception@@QEAA@AEBQEBD@Z" ascii wide
        $s3 = "InitializeCriticalSectionEx" ascii wide
        $s4 = "??0exception@@QEAA@AEBV0@@Z" ascii wide
        $s5 = "?what@exception@@UEBAPEBDXZ" ascii wide
        $s6 = "SetUnhandledExceptionFilter" ascii wide

… [368 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-MASTER-v2.md` exists=`True` bytes=`22885` mtime=`2026-08-05T07:09:41.313572+00:00`
  - sha256: `a08c8e9d21a15d5166f674449247282b9457707917b7cde417243f02a465ca84`
- **REPORT_MASTER_v3:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-MASTER-v3.md` exists=`True` bytes=`57786` mtime=`2026-08-05T07:16:30.475302+00:00`
  - sha256: `807d24e9a4a02bca4a7d7c62b922041282ad25c855d9d510c15cd3bed4c16c85`
- **REPORT_v2:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-v2.md` exists=`True` bytes=`22885` mtime=`2026-08-05T07:09:41.313572+00:00`
  - sha256: `a08c8e9d21a15d5166f674449247282b9457707917b7cde417243f02a465ca84`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`61898` mtime=`2026-08-05T07:11:46.074575+00:00`
  - sha256: `5ba058bdd592e22fb47975b93a01ea6b3d086a9d642d289469fc6971f325472a`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`55016` mtime=`2026-08-05T07:18:31.492629+00:00`
  - sha256: `cb278cd2a8344be78e3a767e9d138a66a2bf3f7e95ab55e1298edbd66b660a56`
- **report_v2_json:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/report-v2.json` exists=`True` bytes=`25563` mtime=`2026-08-05T07:11:46.079575+00:00`
  - sha256: `188da0a5c1feb80794eaf30c1e7b3c20ca1a01e1f60466eb09b961dffcaacc97`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | Malicious: Vidar Infostealer |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE64, IsWindowsGUI, HasDebugData, HasRichSignature, Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL, anti_dbg, escalate_priv). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Vidar
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Vidar Infostealer Disguised as NSudo (SHA256: 0c00aedf97071653467dc
… [21969 more chars]
```


#### v3_excerpt

```
# RE Report — 0c00aedf9707
_Generated 2026-08-05T07:16:30.471322+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=22.83s -->

## Executive Summary
| Top-Line Metric | Value |
|-----------------|-------|
| Final Verdict | Malicious |
| Malware Family | Vidar info-stealer |
| Classification Confidence | High (LLM and v1 model agreement) |
| Static Detection Signal | 15 YARA matches, 27 capa rule hits |

The analyzed 64-bit Windows PE sample (SHA256: `0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5`) is confirmed malicious, attributed to the Vidar information-stealing malware family, with high classification confidence from dual agreement between the v1 static analysis model and LLM judge, suppor
… [56868 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
