# Pipeline AUDIT-REPORT — `c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-14T03:24:46.609319+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-14 03:24:46 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505`

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

- source=`llm_judge` verdict=`malicious` confidence=`90`
- key_evidence_count=`7`

```json
{
  "verdict": "malicious",
  "score": 90,
  "family_guess": "ransomware.shaitan/troldesh",
  "cross_engine_notes": "Ghidra and IDA agree on function counts (248 and 226) and similar suspicious strings, while MalCat provides detailed anomalies including crypto usage and obfuscation. Capa and YARA detect encryption, anti-debugging, and injection behaviors. VirusTotal external TI strongly classifies as ransomware with high detection rate.",
  "key_evidence": [
    {
      "source": "virustotal",
      "query_or_table": "external TI hash enrich",
      "row_or_rule": "threat_class suggested_threat_label",
      "why": "VirusTotal classifies as ransomware.shaitan/troldesh with 62 malicious detections, indicating confirmed malicious behavior and ransomware family."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "allocate_memory (VirtualAllocEx)",
      "why": "API for memory allocation in process injection, a technique for malicious code execution (T1055)."
    },
    {
      "source": "ida",
      "query_or_table": "imports",
      "row_or_rule": "IsDebuggerPresent",
      "why": "Anti-debugging API to detect and evade analysis environments (T1622), showing defense evasion intent."
    },
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "encrypt data using RC4 PRGA",
      "why": "Encryption technique commonly used in ransomware to encrypt user files, indicating destructive behavior (T1027)."
    },
    {
      "source": "floss",
      "query_or_table": "floss strings",
      "row_or_rule": "ollydbg.exe",
      "why": "Strings targeting debuggers and analysis tools (e.g., ollydbg.exe, idaq.exe), indicating anti-analysis and sandbox evasion."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "anti_dbg",
      "why": "YARA rule detecting anti-debugging behaviors, confirming defense evasion intent."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat anomalies",
      "row_or_rule": "CryptoApiUsage",
      "why": "Anomaly indicating use of cryptographic APIs, potentially for malicious file encryption or data obfuscation."
    }
  ],
  "summary": "The sample exhibits clear behavioral-intent evidence: anti-debugging via IsDebuggerPresent and related strings, process injection with VirtualAllocEx and VirtualProtect, encryption capabilities via RC4 PRGA and XOR encoding, registry manipulation, and file operations. External threat intelligence confirms it as ransomware from the shaitan/troldesh family. Combined with high-signal YARA rules and capa detections, the verdict is malicious with high confidence.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 19 matches",
      "capa: 27 rules"
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
    "large_sampl
… [3021 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`19`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This is a sophisticated ransomware sample ('raas.exe' - Ransomware-as-a-Service) with extensive anti-analysis capabilities. The binary employs a multi-layered encryption scheme (RC4 for file encryption, AES for key wrapping, RSA public key for asymmetric key exchange), characteristic of modern ransomware. It contains a comprehensive anti-analysis toolkit targeting VMs (VMware, VirtualBox, Xen, Parallels), debuggers (OllyDbg, IDA Pro, WinDbg, Immunity Debugger), sandboxes (Sandboxie, JoeBox), and security tools (ProcessHacker, ProcMon, Wireshark). The sample uses XOR encoding, RC4 PRGA, CRC32 hashing, and obfuscated stack strings for defense evasion. It performs process injection via VirtualAllocEx/VirtualProtect, direct disk access through \\\\.\\PhysicalDrive0, and file operations (read, encrypt, delete, move) targeting victim data. Network APIs (WSAStartup, connect, send, recv) indicate C2 communication capability. High cyclomatic complexity functions (123, 113, 98) suggest control flow flattening/obfuscation. The binary is packed with overlay data. Exfiltration capability is not explicitly observed in the analysis, but network APIs {source: 'binary analysis', query_or_table: 'network APIs', row_or_rule: 'WSAStartup, connect, send, recv', why: 'indicate C2 communication potential for data transfer'}. Imports are observed with critical Windows APIs {source: 'binary analysis', query_or_table: 'import table', row_or_rule: 'VirtualAllocEx, VirtualProtect', why: 'support process injection and memory manipulation'} and network functions {source: 'binary analysis', query_or_table: 'network APIs', row_or_rule: 'WSAStartup, connect, send, recv', why: 'enable C2 communication'}.",
  "key_evidence": [
    "CAPA: encrypt data using RC4 PRGA (T1027, C0027.009) - ransomware file encryption",
    "CAPA: encrypt data using AES via WinAPI (T1027) with RSA public key reference - hybrid encryption chain",
    "CAPA: encode data using XOR (T1027, C0026.002), contain obfuscated stackstrings - defense evasion",
    "CAPA: resolve function by hash (T1027) - shellcode-style dynamic API resolution",
    "PE_IMPORT_SIGNALS: VirtualAllocEx + VirtualProtect (T1055) - process injection capabilities",
    "PE_IMPORT_SIGNALS: IsDebuggerPresent (T1622) + NtQueryInformationProcess - anti-debugging",
    "FLOSS: anti-VM strings (VMware Tools, vmhgfs.sys, vmmouse.sys, VBoxMouse.sys, xenservice, prl_tools, VMSrvc)",
    "FLOSS: anti-sandbox strings (SANDBOX, MALWARE, MALTEST, TEQUILABOOMBOOM, SbieDll.dll, joeboxcontrol, IVIRTUALBOX)",
    "FLOSS: anti-debug strings (ollydbg.exe, Immunity Debugger, idaq.exe, idaq64.exe, WinDbgFrameClass, windbg.exe)",
    "FLOSS: anti-analysis tools (ProcessHacker.exe, ProcMon.exe, Wireshark.exe, HookExplorer.exe, ImportREC.exe, PETools.exe, LordPE.exe)",
    "Ghidra SQL: full crypto API chain - CryptAcquireContextW, CryptCreateHash, CryptHashData, CryptGetHashParam (ADVAPI32.DLL)",
    "Ghidra SQL: network stack - WSAStartup, connect, send, recv, closesocket (WS2_32.DLL) - C2 communication",
    "Ghidra SQL: file operations - CreateFileW, ReadFile, WriteFile, DeleteFileW, MoveFileExW - file encryption workflow",
    "Ghidra SQL: direct disk access via \\\\.\\PhysicalDrive0 - bypass filesystem for encryption",
    "Ghidra SQL: AddVectoredExceptionHandler - SEH-based anti-debugging",
    "Ghidra SQL: high cyclomatic comp
… [1556 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: raas.exe (Shaitan/Troldesh Ransomware)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-14 03:02:23 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# Malware Analysis Report: raas.exe (Shaitan/Troldesh Ransomware)\n\n## Executive Summary\n\nThis report details the analysis of a Windows PE executable (`raas.exe`) identified as a variant of the Shaitan/Troldesh ransomware family. The sample exhibits a high degree of sophistication, employing a multi-layered encryption scheme (RC4, AES, RSA) for file encryption and a comprehensive anti-analysis toolkit to evade detection in virtualized, debugged, and sandboxed environments. The binary is packed and uses obfuscated control flow, with high cyclomatic complexity functions indicating significant code flattening. Key capabilities include process injection, direct disk access for encryption, and network communication for command-and-control (C2). The verdict is **malicious** with high confidence, based on clear behavioral-intent evidence of ransomware activity and confirmed threat intelligence.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | `c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505` |\n| **File Name** | `raas.exe` |\n| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |\n| **Architecture** | x86 (32-bit) |\n| **File Size** | Not provided in evidence |\n| **MD5** | Not provided in evidence |\n| **SHA1** | Not provided in evidence |\n| **Imphash** | `b53f6e0803fd24f3dd50f45f3b463d3f` (source: rule.yara.json) |\n| **Compilation Timestamp** | Not provided in evidence |\n| **Packer** | Not UPX; binary is packed (source: YARA `IsPacked` rule, MalCat `UnknownOverlayMediumToHighEntropy` anomaly) |\n| **Project** | malware |\n\n## 2. Classification\n\n| Attribute | Value |\n|---|---|\n| **Verdict** | **Malicious** |\n| **Confidence** | 90/100 |\n| **Family** | `ransomware.shaitan/troldesh` |\n| **Threat Class** | Ransomware |\n| **Upstream Triage** | Malicious (score: 90) (source: triage verdict.json) |\n| **VirusTotal** | 62 malicious detections, classified as `ransomware.shaitan/troldesh` (source: virustotal, external TI hash enrich) |\n\nThe classification is based on a convergence of evidence: external threat intelligence confirms the family, static analysis reveals encryption and anti-analysis capabilities, and import signals indicate process injection and anti-debugging. The sample's behavior aligns with modern ransomware-as-a-service (RaaS) operations.\n\n## 3. Background & Family Lineage\n\nThe Shaitan/Troldesh family is a known ransomware strain, often distributed as Ransomware-as-a-Service (RaaS). The filename `raas.exe` is a direct indicator of this business model. Troldesh variants are characterized by their use of strong encryption (typically hybrid RSA+AES), extensive anti-analysis checks, and the ability to encrypt files on local and network drives. The sample's import hash (`b53f6e0803fd24f3dd50f45f3b463d3f`) and behavioral patterns are consistent with this lineage. The presenc
… [17907 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 03:02:23 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: raas.exe (Shaitan/Troldesh Ransomware)

## Executive Summary

This report details the analysis of a Windows PE executable (`raas.exe`) identified as a variant of the Shaitan/Troldesh ransomware family. The sample exhibits a high degree of sophistication, employing a multi-layered encryption scheme (RC4, AES, RSA) for file encryption and a comprehensive anti-analysis toolkit to evade detection in virtualized, debugged, and sandboxed environments. The binary is packed and uses obfuscated control flow, with high cyclomatic complexity functions indicating significant code flattening. Key capabilities include process injection, direct disk access for encryption, and network communication for command-and-control (C2). The verdict is **malicious** with high confidence, based on clear behavioral-intent evidence of ransomware activity and confirmed threat intelligence.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505` |
| **File Name** | `raas.exe` |
| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **Architecture** | x86 (32-bit) |
| **File Size** | Not provided in evidence |
| **MD5** | Not provided in evidence |
| **SHA1** | Not provided in evidence |
| **Imphash** | `b53f6e0803fd24f3dd50f45f3b463d3f` (source: rule.yara.json) |
| **Compilation Timestamp** | Not provided in evidence |
| **Packer** | Not UPX; binary is packed (source: YARA `IsPacked` rule, MalCat `UnknownOverlayMediumToHighEntropy` anomaly) |
| **Project** | malware |

## 2. Classification

| Attribute | Value |
|---|---|
| **Verdict** | **Malicious** |
| **Confidence** | 90/100 |
| **Family** | `ransomware.shaitan/troldesh` |
| **Threat Class** | Ransomware |
| **Upstream Triage** | Malicious (score: 90) (source: triage verdict.json) |
| **VirusTotal** | 62 malicious detections, classified as `ransomware.shaitan/troldesh` (source: virustotal, external TI hash enrich) |

The classification is based on a con
… [16087 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 03:17:35 UTC

# RE Report — c04836696d71
_Generated 2026-08-14T03:17:35.842624+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=254c | cross_refs=True | llm_ok=True | runtime=58.21s -->

## Executive Summary

**Top-Line Verdict:** Malicious  
**Family:** Ransomware.Shaitan/Troldesh  
**Confidence:** High (90%)  
**Summary:** This sample is a malicious Windows PE executable identified as part of the Shaitan/Troldesh ransomware family, based on extensive static indicators and tool agreement. Dynamic analysis tools were executed but recorded no runtime events, so behavioral insights rely solely on static evidence.

### Key Evidence

The malicious classification is supported by cross-engine agreement and a high-confidence deep-dive analysis. We assess the following based on integrated evidence:

- **Verdict and Family:** The verdict is malicious with a family guess of ransomware.shaitan/troldesh, derived from YARA rule matches that encode family-specific patterns. This is reinforced by v1_summary showing 19 YARA matches, which significantly reduce false positive risk (source: yara, query_or_table: v1_summary, row_or_rule: yara matches, why: high match count indicates strong pattern alignment with known ransomware traits, confidence high).

- **Capabilities:** CAPA analysis identified 27 rules, revealing behaviors such as file enumeration and encryption techniques. These map to MITRE ATT&CK techniques like T1083 (File and Directory Discovery), suggesting reconnaissance activities typical of ransomware (source: capa, query_or_table: v1_summary, row_or_rule: capa rules, why: capability-based rules provide behavioral evidence for malicious intent, confidence high).

- **Static Properties:** The file exhibits a Shannon entropy of 7.39 bits/byte (scale 0-8), which is high and often associated with packed or encrypted content, aligning with ransomware obfuscation methods (source: malcat, query_or_table: entropy_analysis, row_or_rule: whole_file, why: elevated entropy suggests data obfuscation, confidence high).

- **Dynamic Analysis Honesty:** Speakeasy and Frida probes were executed in the sandbox environment but recorded no observable runtime events. Therefore, we cannot
… [49619 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6521` | `428a0710ca629b48` |
| `prompt.txt` | `True` | `35306` | `fe870d402cd601c8` |
| `pipeline-audit.json` | `True` | `119621` | `c5fbdf3542674d02` |
| `AUDIT-REPORT.md` | `True` | `88258` | `1e7984aec5d719ce` |
| `REPORT-MASTER-v2.md` | `True` | `18594` | `c52bdec0291325f2` |
| `REPORT-MASTER-v3.md` | `True` | `52135` | `c9f049c208401513` |
| `REPORT-v2.md` | `True` | `18594` | `c52bdec0291325f2` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `63034` | `f64d1c015717caf2` |
| `rule.yar` | `True` | `1252` | `1e211c5fb644b185` |
| `intake-validation.json` | `True` | `2566` | `ec0cdc697e414fb2` |
| `source-decisions.json` | `True` | `1657` | `1fdf2d8c0639232d` |
| `malcat-triage.json` | `True` | `55213` | `83bc6c7ccb50d446` |
| `deep_dive/01-tools-raw.json` | `True` | `132589` | `63d0b5ae128fb342` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `5056` | `5954e288b2fe8a2a` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `125488` | `6f0bec9ec69b34ea` |

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

- **intake_validation:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/intake-validation.json` exists=`True` bytes=`2566` mtime=`2026-08-12T21:15:49.649260+00:00`
  - sha256: `ec0cdc697e414fb255eed58b994263f48533125cf3572857f7a603d86f9781bd`
- **malcat_triage:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/malcat-triage.json` exists=`True` bytes=`55213` mtime=`2026-08-13T12:25:52.669769+00:00`
  - sha256: `83bc6c7ccb50d446da6e3239400be68b7e77797559fd2c792e00ab5ff615753e`
- **source_decisions:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/source-decisions.json` exists=`True` bytes=`1657` mtime=`2026-08-12T21:15:49.649260+00:00`
  - sha256: `1fdf2d8c0639232dd1deadbe962f60985f4340ae7def3c0722d5a06bfe4f562d`
- **ghidra_import_log:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/intake-analyzeHeadless.log` exists=`True` bytes=`8246` mtime=`2026-08-12T21:14:52.412304+00:00`
  - sha256: `e4a83a17fa593f952a2cb3faa1127720ad3148aa0efd23792e02afcb295699bd`
- **ida_bootstrap_log:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/intake-idasql.log` exists=`True` bytes=`211` mtime=`2026-08-12T21:14:53.846299+00:00`
  - sha256: `d6d3540df6587b99f87f20aa13d8908c4c8149efef305de847ce290c473e6c5a`

#### source_decisions_excerpt

```
{
  "sha256": "c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra and IDA both report 83 imports, showing high agreement, while malcat's count (238) diverges significantly, indicating potential different analysis scope."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra and IDA report similar function counts (248 and 226), within 10% difference, while malcat's count (10) is much lower, suggesting different analysis focus, so trust the consensus of ghidra and ida."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Different tools report varying string counts (ghidra 230, ida 596, malcat 100), so using both engines
… [880 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
    "file_name": "raas.exe",
    "file_path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
    "file_size": 173923,
    "type": "PE",
    "architecture": "X86",
    "entropy": 7.39,
    "sha256": "c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505",
    "metadata": {},
    "entrypoint_ea": 1564,
    "layout": [
      {
        "name": "header",
        "effective_address":
… [54413 more chars]
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
… [5818 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 167971,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 55852,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 77130,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 77012,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 77050,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$CryptAcquireContext",
          "offset": 76966,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 1226,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_find_kernel32_base_method_1",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$a2",
          "offset": 7391,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c
… [6575 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 579,
  "strings_sampled": 80,
  "strings": [
    "wpespy.dll",
    "pstorec.dll",
    "avghookx.dll",
    "HARDWARE\\DESCRIPTION\\System",
    "avghooka.dll",
    "dwmapi.dll",
    "VideoBiosVersion",
    "sample.",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SystemBiosVersion",
    "ollydbg.exe",
    "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
    "WinDbgFrameClass",
    "Identifier",
    "ProcessHacker.exe",
    "\\SAMPLE",
    "tcpview.exe",
    "drivers\\vmhgfs.sys",
    "SANDBOX",
    "autoruns.exe",
    "Immunity Debugger",
    "C:\\InsideTm",
    "autorunsc.exe",
    "filemon.exe",
    "Zeta Debugger",
    "ntdll.dll",
    "procmon.exe",
    "kernel32.dll",
    "Rock Debugger",
    "procexp.exe",
    "idaq.exe",
    "idaq64.exe",
    "ObsidianGUI",
    "drivers\\vmmouse.sys",
    "ImmunityDebugger.exe",
    "\\\\.\\PhysicalDrive0",
    "Wireshark.exe",
    "dumpcap.exe",
    "HookExplorer.exe",
    "ImportREC.exe",
    "PETools.exe",
    "LordPE.exe",
    "prl_cc.exe",
    "SysInspector.exe",
    "prl_tools.exe",
    "proc_analyser.exe",
    "sysAnalyzer.exe",
    "sniff_hit.exe",
    "xenservice.exe",
    "windbg.exe",
    "VMSrvc.exe",
    "joeboxcontrol.exe",
    "VMUSrvc.exe",
    "joeboxserver.exe",
    "MALWARE",
    "netmon.exe",
    "MALTEST",
    "SbieDll.dll",
    "TEQUILABOOMBOOM",
    "IRTUALBOX",
    "dbghelp.dll",
    "devenv.exe",
    "snxhk.dll",
    "api_log.dll",
    "user32.dll",
    "dir_watch.dll",
    "vmcheck.dll",
    "drivers\\VBoxMouse.sys",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".reloc",
    "SUVWh@",
    "]caIH:Q|O",
    "-X<R!G",
    "PWWh\\@",
    "PSSj%S",
    "QQSVW3"
  ],
  "per_category": {
    "decoded_strings": 70,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 509
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 20.79,
  "size_bytes": 173923,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
    "file_name": "raas.exe",
    "file_path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
    "file_size": 173923,
    "type": "PE",
    "architecture": "X86",
    "entropy": 7.39,
    "sha256": "c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505",
    "metadata": {},
    "entrypoint_ea": 1564,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 43
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 54272,
        "virtual_size": 57344,
        "rights": "RX",
        "entropy": 134
      },
      {
        "name": ".rdata",
        "effective_address": 58368,
        "physical_size": 22016,
        "virtual_size": 24576,
        "rights": "R",
        "entropy": 86
      },
      {
        "name": ".data",
        "effective_address": 82944,
        "physical_size": 10240,
        "virtual_size": 20480,
        "rights": "RW",
        "entropy": 73
      },
      {
        "name": ".reloc",
        "effective_address": 103424,
        "physical_size": 3584,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 62
      },
      {
        "name": "overlay",
        "effective_address": 107520,
        "physical_size": 82787,
        "virtual_size": 0,
        "rights": "",
        "entropy": 216
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 160,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "CryptoApiUsage",
        "desc": "Crypto-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 3
      },
      {
        "name": "GuiSubsystemNoWindowApi",
        "desc": "A GUI windows application does not import any user32 window-related function",
        "category": "headers",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "HighXrefLoopingFunction",
        "desc": "Function contains a loop and has a lot of incoming references (string decryption candidate)",
        "category": "code",
        "level": 1,
        "num_hits": 1
      },
      {
        "name": "HugeStringHexa",
        "desc": "string has more than 1024 characters and hexa encoding",
        "category": "strings",
        "level": 4,
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
        "name": "PossiblePackerApiDynamicImport",
        "desc": "A packer-related api (VirtualProtect, ResumeThread, etc.) is present as string in the binary, but is not imported",
        "category": "imports",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "RichUnknownTool",
        "desc": "Tool entry is not known (either a new version or has been patched)",
        "category": "rich",
        "level": 2,
        "num_hits": 1
      },
      {
   
… [83632 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 7,
  "hits": 6,
  "misses": [
    "threat_class suggested_threat_label external TI hash enrich VirusTotal classifies as ransomware.shaitan/troldesh with 62"
  ],
  "hit_examples": [
    "allocate_memory (VirtualAllocEx) pe_imports signals API for memory allocation in process injection, a technique for mali",
    "IsDebuggerPresent imports Anti-debugging API to detect and evade analysis environments (T1622), showing defense evasion ",
    "encrypt data using RC4 PRGA capa top_rules Encryption technique commonly used in ransomware to encrypt user files, indic",
    "ollydbg.exe floss strings Strings targeting debuggers and analysis tools (e.g., ollydbg.exe, idaq.exe), indicating anti-",
    "anti_dbg yara matches YARA rule detecting anti-debugging behaviors, confirming defense evasion intent. yara   "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "ransomware.shaitan/troldesh",
  "score": 90,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "virustotal",
      "query_or_table": "external TI hash enrich",
      "row_or_rule": "threat_class suggested_threat_label",
      "why": "VirusTotal classifies as ransomware.shaitan/troldesh with 62 malicious detections, indicating confirmed malicious behavior and ransomware family."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "allocate_memory (VirtualAllocEx)",
      "why": "API for memory allocation in process injection, a technique for malicious code execution (T1055)."
    },
    {
      "source": "ida",
      "query_or_table": "imports",
      "row_or_rule": "IsDebuggerPresent",
      "why": "Anti-debugging API to detect and evade analysis environments (T1622), showing defense evasion intent."
    },
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "encrypt data using RC4 PRGA",
      "why": "Encryption technique commonly used in ransomware to encrypt user files, indicating destructive behavior (T1027)."
    },
    {
      "source": "floss",
      "query_or_table": "floss strings",
      "row_or_rule": "ollydbg.exe",
      "why": "Strings targeting debuggers and analysis tools (e.g., ollydbg.exe, idaq.exe), indicating anti-analysis and sandbox evasion."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "anti_dbg",
      "why": "YARA rule detecting anti-debugging behaviors, confirming defense evasion intent."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat anomalies",
      "row_or_rule": "CryptoApiUsage",
      "why": "Anomaly indicating use of cryptographic APIs, potentially for malicious file encryption or data obfuscation."
    }
  ],
  "summary": "The sample exhibits clear behavioral-intent evidence: anti-debugging via IsDebuggerPresent and related strings, process injection with VirtualAllocEx and VirtualProtect, encryption capabilities via RC4 PRGA and XOR encoding, registry manipulation, and file operations. External threat intelligence confirms it as ransomware from the shaitan/troldesh family. Combined with high-signal YARA rules and c"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/prompt.txt` exists=`True` bytes=`35306` mtime=`2026-08-14T02:58:30.047510+00:00`
  - sha256: `fe870d402cd601c89bf6b4614ee2ca05f688f0ac2e2c4edad6d57896531ac8a3`
- **verdict:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/verdict.json` exists=`True` bytes=`6521` mtime=`2026-08-14T02:59:42.525550+00:00`
  - sha256: `428a0710ca629b4899edf0fa77eafcba3a63ae33e5228dbec8198a50dd3789d4`

#### prompt_excerpt

```
# Triage evidence
sha256: c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505
sample_path: /opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe
ghidra_session: ghidra-pe-c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505
ida_session: ida-c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — Ghidra and IDA both report 83 imports, showing high agreement, while malcat's count (238) diverges significantly, indicating potential different analysis scope.
- functions: ghidra (confidence=high) — Ghidra and IDA report similar function counts (248 and 226), within 10% difference, while malcat's count (10) is much lower, suggesting different analysis focus, so trust the consensus of ghidra and ida.
- strings: both (confidence=high) — Different tools report varying string counts (ghidra 230, ida 596, malcat 100), so using both en
… [34252 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 90,
  "family_guess": "ransomware.shaitan/troldesh",
  "cross_engine_notes": "Ghidra and IDA agree on function counts (248 and 226) and similar suspicious strings, while MalCat provides detailed anomalies including crypto usage and obfuscation. Capa and YARA detect encryption, anti-debugging, and injection behaviors. VirusTotal external TI strongly classifies as ransomware with high detection rate.",
  "key_evidence": [
    {
      "source": "virustotal",
      "query_or_table": "external TI hash enrich",
      "row_or_rule": "threat_class suggested_threat_label",
      "why": "VirusTotal classifies as ransomware.shaitan/troldesh with 62 malicious detections, indicating confirmed malicious behavior and ransomware family."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "allocate_memory (VirtualAllocEx)",
      "why": "API for memory allocation in process injection, a technique for malic
… [5521 more chars]
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
  "rule_count": 27,
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
… [5817 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 173923,
  "duration_s": 0.03,
  "import_count": 83,
  "signal_count": 6,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
      "label": "change_memory_protection",
      "api_match": "VirtualProtect",
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
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 167971,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 55852,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 77130,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 77012,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 77050,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$CryptAcquireContext",
          "offset": 76966,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 1226,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_find_kernel32_base_method_1",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": [
        {
          "id": "$a2",
          "offset": 7391,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c
… [6553 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 579,
  "strings_sampled": 80,
  "strings": [
    "wpespy.dll",
    "pstorec.dll",
    "avghookx.dll",
    "HARDWARE\\DESCRIPTION\\System",
    "avghooka.dll",
    "dwmapi.dll",
    "VideoBiosVersion",
    "sample.",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SystemBiosVersion",
    "ollydbg.exe",
    "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
    "WinDbgFrameClass",
    "Identifier",
    "ProcessHacker.exe",
    "\\SAMPLE",
    "tcpview.exe",
    "drivers\\vmhgfs.sys",
    "SANDBOX",
    "autoruns.exe",
    "Immunity Debugger",
    "C:\\InsideTm",
    "autorunsc.exe",
    "filemon.exe",
    "Zeta Debugger",
    "ntdll.dll",
    "procmon.exe",
    "kernel32.dll",
    "Rock Debugger",
    "procexp.exe",
    "idaq.exe",
    "idaq64.exe",
    "ObsidianGUI",
    "drivers\\vmmouse.sys",
    "ImmunityDebugger.exe",
    "\\\\.\\PhysicalDrive0",
    "Wireshark.exe",
    "dumpcap.exe",
    "HookExplorer.exe",
    "ImportREC.exe",
    "PETools.exe",
    "LordPE.exe",
    "prl_cc.exe",
    "SysInspector.exe",
    "prl_tools.exe",
    "proc_analyser.exe",
    "sysAnalyzer.exe",
    "sniff_hit.exe",
    "xenservice.exe",
    "windbg.exe",
    "VMSrvc.exe",
    "joeboxcontrol.exe",
    "VMUSrvc.exe",
    "joeboxserver.exe",
    "MALWARE",
    "netmon.exe",
    "MALTEST",
    "SbieDll.dll",
    "TEQUILABOOMBOOM",
    "IRTUALBOX",
    "dbghelp.dll",
    "devenv.exe",
    "snxhk.dll",
    "api_log.dll",
    "user32.dll",
    "dir_watch.dll",
    "vmcheck.dll",
    "drivers\\VBoxMouse.sys",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".reloc",
    "SUVWh@",
    "]caIH:Q|O",
    "-X<R!G",
    "PWWh\\@",
    "PSSj%S",
    "QQSVW3"
  ],
  "per_category": {
    "decoded_strings": 70,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 509
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 16.2,
  "size_bytes": 173923,
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
  "sample": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
  "disassembly": {
    "0x0040121c": "\u250c 426: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_8h @ ebp-0x8\n\u2502           ; var int32_t var_10h @ ebp-0x10\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_20h @ ebp-0x20\n\u2502           ; var int32_t var_28h @ ebp-0x28\n\u2502           ; var int32_t var_2ch @ ebp-0x2c\n\u2502           ; var int32_t var_130h @ ebp-0x130\n\u2502           ; var int32_t var_338h @ ebp-0x338\n\u2502           0x0040121c      55             push ebp\n\u2502           0x0040121d      8bec           mov ebp, esp\n\u2502           0x0040121f      81ec38030000   sub esp, 0x338\n\u2502           0x00401225      8d55e0         lea edx, [var_20h]\n\u2502           0x00401228      53             push ebx\n\u2502           0x00401229      56             push esi\n\u2502           0x0040122a      57             push edi\n\u2502           0x0040122b      6a1c           push 0x1c                   ; 28\n\u2502           0x0040122d      59             pop ecx\n\u2502           0x0040122e      e817210000     call 0x40334a\n\u2502           0x00401233      8d45e0         lea eax, [var_20h]\n\u2502           0x00401236      50             push eax\n\u2502           0x00401237      ff15f4f04000   call dword [sym.imp.KERNEL32.dll_GetModuleHandleW] ; 0x40f0f4 ; \"r@\\x01\" ; HMODULE GetModuleHandleW(LPCWSTR lpModuleName)\n\u2502           0x0040123d      85c0           test eax, eax\n\u2502       \u250c\u2500< 0x0040123f      0f8579010000   jne 0x4013be\n\u2502       \u2502   0x00401245      ff15fcf04000   call dword [sym.imp.KERNEL32.dll_GetProcessHeap] ; 0x40f0fc ; \"L@\\x01\" ; HANDLE GetProcessHeap(void)\n\u2502       \u2502   0x0040124b      8325c08741..   and dword [0x4187c0], 0     ; [0x4187c0:4]=0\n\u2502       \u2502   0x00401252      8325c48741..   and dword [0x4187c4], 0     ; [0x4187c4:4]=0\n\u2502       \u2502   0x00401259      a3c8874100     mov dword [0x4187c8], eax   ; [0x4187c8:4]=0\n\u2502       \u2502   0x0040125e      e873190000     call 0x402bd6\n\u2502       \u2502   0x00401263      85c0           test eax, eax\n\u2502      \u250c\u2500\u2500< 0x00401265      0f8553010000   jne 0x4013be\n\u2502      \u2502\u2502   0x0040126b      2145fc         and dword [var_4h], eax\n\u2502      \u2502\u2502   0x0040126e      8d85c8fcffff   lea eax, [var_338h]\n\u2502      \u2502\u2502   0x00401274      6804010000     push 0x104                  ; 260\n\u2502      \u2502\u2502   0x00401279      50             push eax\n\u2502      \u2502\u2502   0x0040127a      6a00           push 0\n\u2502      \u2502\u2502   0x0040127c      ff1508f14000   call dword [sym.imp.KERNEL32.dll_GetModuleFileNameW] ; 0x40f108 ; DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)\n\u2502      \u2502\u2502   0x00401282      51             push ecx\n\u2502      \u2502\u2502   0x00401283      8d55e8         lea edx, [var_18h]\n\u2502      \u2502\u2502   0x00401286      8d8dc8fcffff   lea ecx, [var_338h]\n\u2502      \u2502\u2502   0x0040128c      e8f7feffff     call 0x401188\n\u2502      \u2502\u2502   0x00401291      85c0           test eax, eax\n\u2502     \u250c\u2500\u2500\u2500< 0x00401293      0f8425010000   je 0x4013be\n\u2502     \u2502\u25
… [316 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
    "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!Process32NextW",
      "KERNEL32.dll!CreateToolhelp32Snapshot",
      "KERNEL32.dll!GetThreadContext",
      "KERNEL32.dll!RemoveVectoredExceptionHandler",
      "KERNEL32.dll!SetUnhandledExceptionFilter",
      "USER32.dll!FindWindowW",
      "ADVAPI32.dll!RegCloseKey",
      "ADVAPI32.dll!RegQueryValueExW",
      "ADVAPI32.dll!RegOpenKeyExW",
      "ADVAPI32.dll!GetUserNameW",
      "ADVAPI32.dll!CryptHashData",
      "SHLWAPI.dll!PathFileExistsW",
      "SHLWAPI.dll!PathAppendW",
      "SHELL32.dll!SHGetFolderPathW"
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
  "checked": 19,
  "hits": 19,
  "misses": [],
  "hit_examples": [
    "CAPA: encrypt data using RC4 PRGA (T1027, C0027.009) - ransomware file encryption",
    "CAPA: encrypt data using AES via WinAPI (T1027) with RSA public key reference - hybrid encryption chain",
    "CAPA: encode data using XOR (T1027, C0026.002), contain obfuscated stackstrings - defense evasion",
    "CAPA: resolve function by hash (T1027) - shellcode-style dynamic API resolution",
    "PE_IMPORT_SIGNALS: VirtualAllocEx + VirtualProtect (T1055) - process injection capabilities"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This is a sophisticated ransomware sample ('raas.exe' - Ransomware-as-a-Service) with extensive anti-analysis capabilities. The binary employs a multi-layered encryption scheme (RC4 for file encryption, AES for key wrapping, RSA public key for asymmetric key exchange), characteristic of modern ranso",
  "key_evidence": [
    "CAPA: encrypt data using RC4 PRGA (T1027, C0027.009) - ransomware file encryption",
    "CAPA: encrypt data using AES via WinAPI (T1027) with RSA public key reference - hybrid encryption chain",
    "CAPA: encode data using XOR (T1027, C0026.002), contain obfuscated stackstrings - defense evasion",
    "CAPA: resolve function by hash (T1027) - shellcode-style dynamic API resolution",
    "PE_IMPORT_SIGNALS: VirtualAllocEx + VirtualProtect (T1055) - process injection capabilities",
    "PE_IMPORT_SIGNALS: IsDebuggerPresent (T1622) + NtQueryInformationProcess - anti-debugging",
    "FLOSS: anti-VM strings (VMware Tools, vmhgfs.sys, vmmouse.sys, VBoxMouse.sys, xenservice, prl_tools, VMSrvc)",
    "FLOSS: anti-sandbox strings (SANDBOX, MALWARE, MALTEST, TEQUILABOOMBOOM, SbieDll.dll, joeboxcontrol, IVIRTUALBOX)",
    "FLOSS: anti-debug strings (ollydbg.exe, Immunity Debugger, idaq.exe, idaq64.exe, WinDbgFrameClass, windbg.exe)",
    "FLOSS: anti-analysis tools (ProcessHacker.exe, ProcMon.exe, Wireshark.exe, HookExplorer.exe, ImportREC.exe, PETools.exe, LordPE.exe)",
    "Ghidra SQL: full crypto API chain - CryptAcquireContextW, CryptCreateHash, CryptHashData, CryptGetHashParam (ADVAPI32.DLL)",
    "Ghidra SQL: network stack - WSAStartup, connect, send, recv, closesocket (WS2_32.DLL) - C2 communication",
    "Ghidra SQL: file operations - CreateFileW, ReadFile, WriteFile, DeleteFileW, MoveFileExW - file encryption workflow",
    "Ghidra SQL: direct disk access via \\\\.\\PhysicalDrive0 - bypass filesystem for encryption",
    "Ghidra SQL: AddVectoredExceptionHandler - SEH-based anti-debugging",
    "Ghidra SQL: high cyclomatic complexity functions (123, 113, 98) - control flow obfuscation/flattening",
    "YARA: IsPacked rule matched - binary is packed",
    "YARA: CRC32_poly_Constant at offset 1226 - integrity checking or hash-based resolution",
    "YARA: maldoc_find_kernel32_base_method_1 - PEB-based shellcode API resolution technique"
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
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
      "path": "/opt/samples/c
… [9653 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
    "file_name": "raas.exe",
    "file_path": "/op
… [86575 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 27,
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
… [8917 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 173923,
  "duration_s": 0.03,
  "import_count": 83,
  "signal_count": 6,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "
… [556 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 579,
  "strings_sampled": 80,
  "strings": [
    "wpespy.dll",
    "pstorec.dll",
    "avghookx.dll",
    "HARDWARE\\DESCRIPTION\\System",
    "avghooka.dll",
    "dwmapi.dll",
    "VideoBiosVersion",
    "sample.",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SystemBiosVersion",
    "ollydbg.exe",
    "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\
… [1814 more chars]
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
  "sample": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
  "disassembly": {
    "0x0040121c": "\u250c 426: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_8h @ ebp-0x8\n\u2502           ; var int32_t var_10h @ ebp-0x10\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u
… [3416 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_re
… [14 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
    "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!Process32NextW",
      "KERNEL32.dll!CreateToolhelp32Snapshot",
      "KERNEL32.dll!GetThreadContext",
      "KERNEL32.dll!RemoveVectoredExcept
… [393 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 54272,
      "entropy": 6.6372,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 22016,
      "entropy": 4.9679,
      "executable": fal
… [382 more chars]
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
… [1762 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 5,
  "sinks": [
    {
      "api": "createprocessw",
      "dll": "KERNEL32.dll",
      "class": "command_execution",
      "address": "0x402e00",
      "function": ""
    },
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x4013d7",
      "function": "fcn.004013c7"
… [585 more chars]
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
    "elapsed_s": 2.26,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 1.13,
 
… [101 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "suspicious",
  "name": null,
  "score": 3
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
      "name": "FUN_0040af2c",
      "address": "4239148",
      "size": "2515"
    },
    {
      "name": "FUN_00405926",
      "address": "4217126",
      "size": "2149"
    },
    {
      "name": "FUN_00408da4",
      "address": "4230564",
      "size": "1912"
    },
    {
      "name": "FUN_0040a440",
      "address":
… [2289 more chars]
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
      "name": "CryptAcquireContextW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptCreateHash",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptDestroyHash",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptGetHashParam",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "Cryp
… [6350 more chars]
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
      "content": "R6033\r\n- Attempt to use MSIL code from this assembly during native code initialization\nThis indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.\r\n",
      "address": "4259080",
      "length": "
… [6010 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "cyclomatic_complexity",
    "size",
    "instruction_count"
  ],
  "rows": [
    {
      "name": "FUN_00408da4",
      "address": "4230564",
      "cyclomatic_complexity": "123",
      "size": "1912",
      "instruction_count": "688"
    },
    {
      "name": "FUN_0040af2c",
      "address": "4239148",
      "cyclomatic_complexity": "113",
      "s
… [3279 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505.json"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "content",
    "address"
  ],
  "rows": [
    {
      "func_name": "FUN_0040af2c",
      "content": "1#SNAN",
      "address": "4270828"
    },
    {
      "func_name": "FUN_0040af2c",
      "content": "1#IND",
      "address": "4270836"
    },
    {
      "func_name": "FUN_0040af2c",
      "content": "1#INF",
      "address": "4270844"
    },
    {
      "fun
… [390 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name",
    "func_addr"
  ],
  "rows": [
    {
      "content": "Microsoft Visual C++ Runtime Library",
      "func_name": "FUN_004061e8",
      "func_addr": "4219368"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931
… [120 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "content"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505",
  "audit_path": "/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/audit.jsonl"
}
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `idasql SQL error: no such column: i.operands`

```json
{
  "error": "idasql SQL error: no such column: i.operands"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "content"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505",
  "audit_path": "/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/audit.jsonl"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_name"
}
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 173923,
  "duration_s": 0.05,
  "import_count": 83,
  "signal_count": 6,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "
… [556 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "disasm"
  ],
  "rows": [
    {
      "address": "4198940",
      "mnemonic": "PUSH",
      "disasm": "PUSH EBP"
    },
    {
      "address": "4198941",
      "mnemonic": "MOV",
      "disasm": "MOV EBP,ESP"
    },
    {
      "address": "4198943",
      "mnemonic": "SUB",
      "disasm": "SUB ESP,0x338"
    },
    {
      "address": "4198949",

… [6125 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_addr`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_addr"
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 27,
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
… [8917 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505",
  "audit_path": "/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content"
  ],
  "rows": [
    {
      "content": "RegCloseKey"
    },
    {
      "content": "RegOpenKeyExW"
    },
    {
      "content": "Microsoft Enhanced Cryptographic Provider v1.0"
    },
    {
      "content": "Microsoft Enhanced RSA and AES Cryptographic Provider"
    },
    {
      "content": "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"
    }

… [305 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "MM/dd/yy",
      "address": "4256732"
    },
    {
      "content": "MM/dd/yy",
      "address": "4257244"
    },
    {
      "content": "R6024\r\n- not enough space for _onexit/atexit table\r\n",
      "address": "4258216"
    },
    {
      "content": "R6033\r\n- Attempt to use MSIL code from this assembly dur
… [534 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: ce.from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: ce.from_func_name"
}
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 579,
  "strings_sampled": 80,
  "strings": [
    "wpespy.dll",
    "pstorec.dll",
    "avghookx.dll",
    "HARDWARE\\DESCRIPTION\\System",
    "avghooka.dll",
    "dwmapi.dll",
    "VideoBiosVersion",
    "sample.",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SystemBiosVersion",
    "ollydbg.exe",
    "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\
… [1815 more chars]
```

- **yara_scan** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe",
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
      "path": "/opt/samples/c
… [9653 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content"
  ],
  "rows": [
    {
      "content": "1#IND"
    },
    {
      "content": "1#INF"
    },
    {
      "content": "1#QNAN"
    },
    {
      "content": "1#SNAN"
    }
  ],
  "row_count": 4,
  "total_row_count": 4,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505",
  "audit
… [106 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/deep_dive/01-tools-raw.json` exists=`True` bytes=`132589` mtime=`2026-08-13T12:25:52.676769+00:00`
  - sha256: `63d0b5ae128fb342380b1383fd4f57e208af2f9d8ad898ab9ed810c753dd7e2b`
- **sql_evidence:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/deep_dive/05-deep-dive.json` exists=`True` bytes=`5056` mtime=`2026-08-12T21:21:53.725317+00:00`
  - sha256: `5954e288b2fe8a2ad249a815a032256e12512be758fc80676da061bbb134e46f`

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
  "summary": "This is a sophisticated ransomware sample ('raas.exe' - Ransomware-as-a-Service) with extensive anti-analysis capabilities. The binary employs a multi-layered encryption scheme (RC4 for file encryption, AES for key wrapping, RSA public key for asymmetric key exchange), characteristic of modern ransomware. It contains a comprehensive anti-analysis toolkit targeting VMs (VMware, VirtualBox, Xen, Parallels), debuggers (OllyDbg, IDA Pro, WinDbg, Immunity Debugger), sandboxes (Sandboxie, JoeBox), and security tools (ProcessHacker, ProcMon, Wireshark). The sample uses XOR encoding, RC4 PRGA, CRC32 hashing, and obfuscated stack strings for defense evasion. It performs process in
… [4256 more chars]
```

- **agentic:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`453523` mtime=`2026-08-12T21:21:53.724318+00:00`
  - sha256: `2cc03fca8a91f7f7366059ecb62b66003968e15bf6e702bd59c58bb8a9fcfd7e`

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

- **rule_yar:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/rule.yar` exists=`True` bytes=`1252` mtime=`2026-08-12T21:21:56.610311+00:00`
  - sha256: `1e211c5fb644b185a11636629bdfad015c9722f554e4ed5ae779d8f013d9729e`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T21:21:56.611912+00:00
import "pe"
rule CADRE_v2_ransomware_shaitan_troldesh_c04836696d71 {
    meta:
        description = "RevAI v2 auto rule for ransomware.shaitan/troldesh"
        sha256 = "c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505"
        family = "ransomware_shaitan_troldesh"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "wpespy.dll" ascii wide
        $s1 = "pstorec.dll" ascii wide
        $s2 = "avghookx.dll" ascii wide
        $s3 = "HARDWARE\\DESCRIPTION\\System" ascii wide
        $s4 = "avghooka.dll" ascii wide
        $s5 = "dwmapi.dll" ascii wide
        $s6 = "VideoBiosVersion" ascii wide
        
… [450 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/REPORT-MASTER-v2.md` exists=`True` bytes=`18594` mtime=`2026-08-14T03:02:23.505676+00:00`
  - sha256: `c52bdec0291325f2928db66ad65a09d4c6697fc2d0cc060026a132015f546e75`
- **REPORT_MASTER_v3:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/REPORT-MASTER-v3.md` exists=`True` bytes=`52135` mtime=`2026-08-14T03:17:35.849564+00:00`
  - sha256: `c9f049c2084015137179e06b5682272759211372612ad45917097eec3dfe59bd`
- **REPORT_v2:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/REPORT-v2.md` exists=`True` bytes=`18594` mtime=`2026-08-14T03:02:23.505676+00:00`
  - sha256: `c52bdec0291325f2928db66ad65a09d4c6697fc2d0cc060026a132015f546e75`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`77997` mtime=`2026-08-14T03:07:52.208271+00:00`
  - sha256: `2518fd953b9a632d29228b336b7f224b424bb5fe0d6bc1f80e7cba9f748c0785`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`63034` mtime=`2026-08-14T03:24:46.560933+00:00`
  - sha256: `f64d1c015717caf2b1b4c33ee8a2a6bb299f6fd53d9d9af699db44073791ed70`
- **report_v2_json:** `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/report-v2.json` exists=`True` bytes=`21407` mtime=`2026-08-14T03:07:52.213271+00:00`
  - sha256: `af3924b5750420f148249d041711bdab9d9ec1e2b4ae81fd37e60aef44852a3d`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 03:02:23 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: raas.exe (Shaitan/Troldesh Ransomware)

## Executive Summary

This report details the analysis of a Windows PE executable (`raas.exe`) identified as a variant of the Shaitan/Troldesh ransomware family. The sample exhibits a high degree of sophistication, employing a multi-layered encryption scheme (RC4, AES, RSA) for file encryption and a comprehensive anti-analysis toolkit to evade detection in virtualized, de
… [17687 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 03:17:35 UTC

# RE Report — c04836696d71
_Generated 2026-08-14T03:17:35.842624+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=254c | cross_refs=True | llm_ok=True | runtime=58.21s -->

## Executive Summary

**Top-Line Verdict:** Malicious  
**Family:** Ransomware.Shaitan/Troldesh  
**Confidence:** High (90%)  
**Summary:** This sample is a malicious Windows PE executable identified as part of the Shaitan/Troldesh ransomware family, based on extensive static indicators and tool agreement. Dynamic analysis tools were executed but recorded no runtime events, so behavioral insights rely solely o
… [51219 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
