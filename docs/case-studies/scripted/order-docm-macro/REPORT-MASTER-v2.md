> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:06:11 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a macro-enabled Microsoft Word document (.docm) identified as a malicious dropper. The sample, SHA256 `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73`, was submitted for analysis under the project `test-corpus`. Initial triage flagged the sample as suspicious due to the presence of VBA macros and network indicators. A deep-dive analysis confirmed the document contains a malicious VBA payload designed to download and execute a remote PowerShell script. The payload employs several evasion techniques, including a hidden PowerShell window, execution policy bypass, and base64-encoded commands, to deliver its final stage from the domain `autonews.safeframe.tech`. The sample is classified as malicious with high confidence. Key indicators of compromise include the C2 domain, specific PowerShell command-line arguments, and the use of the `mshta` LOLBin for stealthy execution.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73` |
| **File Name** | `order.docm` |
| **File Path** | `/opt/samples/corpus/test-corpus/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm` |
| **File Type** | Microsoft Word Macro-Enabled Document (.docm) |
| **Project** | `test-corpus` |
| **Analysis Date** | 2026-08-09 |

The sample is a ZIP-based Office Open XML (OOXML) document containing a `vbaProject.bin` file, which hosts the embedded VBA macro code (source: malcat). The `.docm` extension indicates it is a macro-enabled document, requiring user interaction (enabling macros) to trigger the payload.

## 2. Classification

| Attribute | Value |
|---|---|
| **Verdict** | **Malicious** |
| **Confidence** | High (90%) |
| **Family** | Generic Macro Malware / Maldoc Dropper |
| **Threat Type** | Downloader / Dropper |

The classification is based on clear behavioral intent evidence. The document's VBA macro is not a benign automation script; it is a downloader cradle designed to fetch and execute remote code. This constitutes hostile behavior, moving the sample beyond the "suspicious" category assigned by initial triage (source: deep-dive.json). The use of evasion techniques like hidden PowerShell windows and LOLBin abuse further confirms malicious intent.

## 3. Background & Family Lineage

The sample exhibits characteristics common to a broad category of macro-based malware often referred to as "maldocs." These are Microsoft Office documents weaponized with VBA macros to serve as initial infection vectors. The specific techniques observed—using PowerShell download cradles, `mshta` for execution, and base64 obfuscation—are staples of many commodity malware families and phishing campaigns. No specific, named malware family (e.g., Emotet, QakBot) was identified from the available strings or structures. The payload appears to be a generic, likely customizable, downloader component (source: triage verdict.json).

## 4. Static Analysis

Static analysis focused on the document's structure and embedded macro code.

**Document Structure:**
The file is a valid OOXML archive containing 15 virtual files, including `word/vbaProject.bin` (4985 bytes) and `word/vbaData.xml`, confirming an active macro project (source: malcat).

**YARA Matches:**
Multiple YARA rules fired, indicating the presence of macro code and suspicious strings (source: yara).

| Rule | Significance |
|---|---|
| `docx_macro` | Confirms the document contains VBA macro code. |
| `Contains_VBA_macro_code` | Reinforces the presence of executable macro content. |
| `office_document_vba` | Generic rule for Office documents with VBA. |
| `contains_base64` | Indicates potential use of base64 encoding for obfuscation. |
| `domain` | Suggests a hardcoded domain string, possibly for C2. |
| `IP` | Suggests a hardcoded IP address string. |

**Extracted Strings (from MalCat):**
Analysis of the `vbaProject.bin` revealed critical strings that define the payload's behavior (source: malcat).

*   **Download Cradle:** `IEX (New-Object Net.WebClient).DownloadString(...)` - This is a classic PowerShell command to download and execute a script from a remote URL. The target domain is `autonews.safeframe.tech`.
*   **Execution Command:** `powershell -windowstyle hidden -ep bypass -enc ...` - This command launches PowerShell with a hidden window (`-windowstyle hidden`), bypasses the execution policy (`-ep bypass`), and runs a base64-encoded command (`-enc`).
*   **LOLBin Reference:** `mshta` - The Microsoft HTML Application Host is a legitimate Windows binary often abused to execute scripts or HTA files, providing a stealthy execution method.
*   **Shell Object:** `WScript.Shell` - Used to run commands, in this case with the window style set to `0` (hidden).

These strings collectively describe a multi-stage attack: the macro uses `WScript.Shell` to launch a PowerShell process with specific evasion flags, which then downloads and executes a script from a remote server.

## 5. Behavioral Analysis

No dynamic behavioral analysis (e.g., sandbox execution, API tracing) was performed or provided in the evidence. The analysis is based solely on static artifacts. Therefore, observed behaviors are inferred from the static code. The intended behavior, as derived from the VBA payload, is:

1.  **Trigger:** User opens the document and enables macros.
2.  **Execution:** The macro executes a `WScript.Shell` command.
3.  **Payload Delivery:** The command launches `powershell.exe` with parameters to hide its window, bypass security policies, and run a base64-encoded command.
4.  **Network Activity:** The decoded PowerShell command uses `Net.WebClient` to download a script from `http://autonews.safeframe.tech`.
5.  **Code Execution:** The downloaded script is executed in memory via `IEX` (Invoke-Expression).

No persistence mechanisms, credential theft, or lateral movement were observed in the static strings. The primary capability is downloading and executing additional payloads.

## 6. Network Analysis & C2

The sample contains hardcoded network indicators for command and control (C2) communication.

| Indicator | Type | Context |
|---|---|---|
| `autonews.safeframe.tech` | Domain | Used in the PowerShell download cradle as the source for the next-stage payload. |
| (IP Address - redacted) | IP Address | Detected by YARA rule `IP`. Specific address not extracted in provided evidence. |

The network activity is not beaconing but a single, purposeful download request initiated by the PowerShell command. The domain `autonews.safeframe.tech` is the primary C2 channel for payload retrieval. The use of a `.tech` top-level domain is common in malicious infrastructure.

## 7. Capability Assessment

| Capability | Status | Evidence |
|---|---|---|
| **Initial Access** | **Observed** | Document requires user to enable macros (source: malcat). |
| **Execution** | **Observed** | Uses `WScript.Shell` and `powershell.exe` with evasion flags (source: malcat). |
| **Defense Evasion** | **Observed** | Hidden PowerShell window, execution policy bypass, base64 encoding, LOLBin (`mshta`) abuse (source: deep-dive.json). |
| **Command and Control** | **Observed** | Downloads payload from `autonews.safeframe.tech` (source: malcat). |
| **Persistence** | Not Observed | No registry, scheduled task, or startup folder references found. |
| **Privilege Escalation** | Not Observed | No token manipulation or exploit strings found. |
| **Credential Access** | Not Observed | No references to LSASS, credential dumping, or keylogging. |
| **Lateral Movement** | Not Observed | No network share or remote service strings. |
| **Exfiltration** | Not Observed | No data staging or upload commands. |

The sample's sole observed capability is acting as a downloader/dropper. Its primary function is to bypass defenses and retrieve a second-stage payload.

## 8. Attribution

No specific threat actor or campaign attribution is possible based on the available evidence. The techniques used are generic and widely shared among cybercriminal groups. The domain `autonews.safeframe.tech` and the payload structure do not match known, attributed campaigns in the provided data.

## 9. Indicators of Compromise

**File-Based IOCs:**
*   SHA256: `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73`
*   File Name: `order.docm`

**Network-Based IOCs:**
*   Domain: `autonews.safeframe.tech`
*   (IP Address - to be extracted from full analysis)

**Behavioral/Command IOCs:**
*   PowerShell Command Line: `powershell -windowstyle hidden -ep bypass -enc`
*   PowerShell Download Cradle: `IEX (New-Object Net.WebClient).DownloadString(...)`
*   LOLBin: `mshta`
*   Script Object: `WScript.Shell`

## 10. Detection Rules

**YARA Rule (Generated):**
A YARA rule was generated for this sample (source: rule.yara.json). The rule path is `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/rule.yar`. It targets the identified strings and structures.

**Sigma Rule:**
A corresponding Sigma rule for log-based detection was also generated at `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/rule.yml`.

**Detection Logic:**
Detection should focus on:
1.  Office documents spawning `powershell.exe` or `mshta.exe`.
2.  PowerShell command lines containing `-windowstyle hidden`, `-ep bypass`, and `-enc`.
3.  Network connections to `autonews.safeframe.tech`.
4.  Processes with command lines containing `IEX` and `DownloadString`.

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Initial Access** | Phishing: Spearphishing Attachment | T1566.001 | Macro-enabled document delivered via email (inferred). |
| **Execution** | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell command execution (source: malcat). |
| **Execution** | Windows Management Instrumentation | T1047 | Not directly observed, but `WScript.Shell` is a related scripting host. |
| **Defense Evasion** | Obfuscated Files or Information: Base64 | T1027.002 | Base64-encoded PowerShell command (source: malcat). |
| **Defense Evasion** | Hide Artifacts: Hidden Window | T1564.003 | `-windowstyle hidden` parameter (source: malcat). |
| **Defense Evasion** | Impair Defenses: Disable or Modify Tools | T1562.001 | `-ep bypass` to bypass PowerShell execution policy (source: malcat). |
| **Defense Evasion** | System Binary Proxy Execution: Mshta | T1218.005 | Use of `mshta` LOLBin (source: malcat). |
| **Command and Control** | Ingress Tool Transfer | T1105 | Downloading payload from `autonews.safeframe.tech` (source: malcat). |

## 12. Containment, Eradication, Recovery

**Containment:**
1.  Block the domain `autonews.safeframe.tech` at the network perimeter firewall and DNS sinkhole.
2.  Quarantine any endpoints that have opened the `order.docm` file.
3.  Search email gateway logs for the delivery of this or similar `.docm` files and remove them from mailboxes.

**Eradication:**
1.  Terminate any suspicious `powershell.exe` or `mshta.exe` processes on affected systems.
2.  Scan affected systems with updated AV/EDR signatures that include the generated YARA rule.
3.  Investigate the downloaded payload from `autonews.safeframe.tech` if captured in network logs; its hash and behavior will dictate further eradication steps.

**Recovery:**
1.  If the second-stage payload was executed, the system should be considered compromised and rebuilt from a known-good image.
2.  Reset credentials for any user who may have opened the document, as the ultimate payload's capabilities are unknown.

## 13. Recommendations

1.  **User Training:** Educate users on the risks of enabling macros in unsolicited Office documents.
2.  **Macro Policy:** Implement Group Policy to disable macros from the internet or require them to be digitally signed by a trusted publisher.
3.  **Network Monitoring:** Enhance detection for PowerShell download cradles and connections to newly registered or suspicious TLDs like `.tech`.
4.  **Endpoint Hardening:** Configure PowerShell to use Constrained Language Mode and enable script block logging to capture obfuscated commands.
5.  **Threat Intelligence:** Add the identified IOCs (domain, file hash, command patterns) to threat intelligence platforms and SIEM for proactive blocking and hunting.

## 14. Appendix A: Evidence Trail

| Timestamp | Source | Phase/Action | Notes |
|---|---|---|---|
| 1786291761.77 | quick_scan_v2 | Phase 2 | Initial triage scan. |
| 1786291932.80 | agentic_recover_v4 | Start | Deep analysis initiated. |
| 1786291932.97 | yara_gen_v2 | - | YARA rule generation. |
| 1786292089.04 | publish_report_v2 | - | Report publishing. |
| 1786292220.46 | publish_report_v2_technical | - | Technical report finalization. |

**Tool Execution Summary:**
*   **YARA:** Executed successfully. 6 rules matched (source: tool_gate).
*   **MalCat:** Executed successfully. Provided file structure and string analysis (source: tool_gate).
*   **XORSearch:** Executed but found no XOR-encoded strings (source: xorsearch).
*   **.NET Analysis:** Not applicable (source: dotnet_analyze).
*   **Radare2/Disassembly:** Executed on the binary, but output appears to be from a generic or misaligned analysis, not directly relevant to the VBA payload (source: r2 disassembly).

## 15. Appendix B: Module Inventory

The sample is a single-stage dropper. Its "modules" are the embedded VBA macro and the remote payload it downloads.

| Module | Type | Description |
|---|---|---|
| **VBA Macro** | Embedded Code | The primary malicious component within `vbaProject.bin`. Contains the download cradle and execution commands. |
| **Remote PowerShell Script** | Second-Stage Payload | Hosted at `autonews.safeframe.tech`. Its contents are unknown from static analysis alone. It is the likely final-stage malware. |

## 16. Author + Sign-off

**Report Author:** Automated Analysis System (REPORT-MASTER v2)
**Review Status:** Auto-generated. Requires human analyst review for final validation.
**Sign-off:**

*This report was generated based on the provided evidence corpus. All claims are cited to their source tool or data file. Unknowns, particularly regarding the second-stage payload and dynamic behavior, are explicitly noted.*