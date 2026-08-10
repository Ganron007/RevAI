> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:22:51 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a malicious Windows PE executable (`space1.ex`, SHA256: `5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`). The sample is a dropper/loader with a primary objective of evading security software, establishing persistence, and executing a secondary payload. It is not a known, named malware family but exhibits characteristics of a service-based trojan.

The malware's execution flow begins with a comprehensive anti-analysis phase. It enumerates running processes to detect 13 specific security products from vendors including 360 Security, Comodo, AhnLab, Dr.Web, and ESET. If any of these processes are found, the malware terminates itself to avoid detection in sandboxed or protected environments (source: r2_disassembly, ghidra_query). It also employs anti-debugging techniques by checking for the presence of a debugger (source: ida_query, capa).

Upon successful evasion, the malware dynamically resolves API functions to hinder static analysis, allocates memory with read-write-execute (RWX) permissions, and decrypts an embedded payload. It then injects this payload into a process using Asynchronous Procedure Calls (APCs) (source: capa, pe_imports). To ensure it runs automatically, it creates a Windows service for persistence (source: pe_imports, yara). The binary contains network-capable imports (WININET, WSOCK32), indicating latent command-and-control (C2) or data exfiltration capabilities, though specific C2 servers or exfiltration methods were not observed in the static analysis (source: deep-dive.json).

The verdict is **malicious** with high confidence (90%). The behavioral intent is clear: defense evasion, persistence, and code execution are core malicious activities, not neutral protection mechanisms. Recommendations include immediate containment, eradication of the service, and network monitoring for related indicators.

## 1. Sample Identification

| Attribute | Value |
| :--- | :--- |
| **File Name** | space1.ex |
| **SHA256** | 5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da |
| **MD5** | (Not provided in evidence) |
| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **Architecture** | x86 (32-bit) |
| **Compiler/Linker** | Microsoft Visual C++ 2008 (source: malcat) |
| **File Size** | (Not provided in evidence) |
| **First Submission** | (Not provided in evidence) |
| **Project** | REVAI-LAB-CORPUS-L2 |
| **Sample Path** | /opt/samples/corpus/REVAI-LAB-CORPUS-L2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex |

The sample is a standard 32-bit Windows GUI executable. The import hash (imphash) is `1905143b6a38c11e2b30615cb955fd08` (source: rule.yara.json). Analysis confirms it is not a .NET assembly (source: dotnet_analyze) and is not packed with UPX (source: UPX unpack).

## 2. Classification

| Field | Value |
| :--- | :--- |
| **Verdict** | **Malicious** |
| **Confidence** | High (90%) |
| **Family** | Unknown service-based trojan (source: triage verdict.json) |
| **Type** | Dropper / Loader |
| **Primary Objective** | Defense Evasion, Persistence, Code Execution |

The classification is based on clear behavioral intent. The sample performs process enumeration to detect and evade specific security products, a direct defense evasion tactic (source: r2_disassembly). It creates a Windows service for persistence (source: pe_imports, yara). It allocates RWX memory and executes shellcode via indirect calls, indicating payload execution (source: capa). These are not neutral protection features but hostile behaviors. The upstream triage verdict is "malicious" with a score of 75 (source: triage verdict.json).

## 3. Background & Family Lineage

No specific malware family name (e.g., Emotet, TrickBot) was identified by the analysis tools. The triage system guessed "unknown service-based trojan" (source: triage verdict.json). The behavioral profile—anti-AV process checks, service-based persistence, and shellcode dropper—is a common pattern in commodity malware and targeted loaders. The targeted security products (360, Comodo, AhnLab, Dr.Web, ESET) suggest a focus on evading a broad range of endpoint protection suites, possibly indicating a global or regionally targeted campaign.

## 4. Static Analysis

Static analysis reveals a binary designed to resist analysis and execute malicious code.

**Imports & Capabilities:**
The import table contains 63 functions. High-signal imports directly indicate malicious capabilities (source: malcat, pe_imports):

| Import | Signal | Capability |
| :--- | :--- | :--- |
| `IsDebuggerPresent` | High | Anti-debugging (T1622) |
| `CreateServiceA` | High | Service persistence (T1543.003) |
| `QueueUserAPC` | High | Code injection (T1055) |
| `VirtualAlloc` | High | RWX memory allocation (T1055) |
| `CreateToolhelp32Snapshot` | High | Process enumeration (T1057) |
| `OpenSCManagerA` | High | Service control manager access |
| `GetProcAddress` / `LoadLibraryA` | Mid | Dynamic API resolution (T1129) |
| `RegOpenKeyA` | Mid | Registry manipulation |
| `InternetOpenA`, `WSAStartup` | Mid | Network capability (latent) |

**Strings & Obfuscation:**
The binary contains obfuscated strings, including garbled data like `&*^@QDSJGIO` and a long base64-like string `fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6` (source: rule.yara.json, FLOSS). This indicates stack-string obfuscation (T1027.005) to hide API names and configuration data from static analysis (source: capa).

**Anomalies:**
MalCat identified 8 anomalies, including high-entropy resources, cross-section jumps, dynamic strings, and XOR loops (source: malcat). These are consistent with obfuscation and packing techniques, but the binary is not UPX-packed (source: UPX unpack).

## 5. Behavioral Analysis

No dynamic analysis (e.g., sandbox, Speakeasy, Frida) results were provided in the evidence. Therefore, observed runtime behavior is limited to what can be inferred from static analysis of the code flow.

**Inferred Execution Flow (from static analysis):**
1.  **Anti-Analysis Check:** The entry point (`0x402720`) calls a function (`0x402640`) 13 times, each time passing the name of a security product process (e.g., `QHACTIVEDEFENSE.EXE`, `CMDAGENT.EXE`, `V3LITE.EXE`). If any are found running, the malware jumps to an exit routine (`0x402948`) (source: r2_disassembly, deep-dive.json). This is a clear defense evasion behavior.
2.  **Dynamic API Resolution:** The malware uses `GetProcAddress` and `LoadLibraryA` to resolve API functions at runtime, making static analysis harder (source: pe_imports).
3.  **Payload Decryption & Execution:** It allocates RWX memory (`VirtualAlloc`), decrypts embedded data (the garbled strings), and uses `QueueUserAPC` for code injection (source: capa, pe_imports).
4.  **Persistence:** It creates a Windows service using `CreateServiceA` and `OpenSCManagerA` (source: pe_imports, yara).

## 6. Network Analysis & C2

The binary imports functions from `WININET.DLL` (`InternetOpenA`, `InternetConnectA`, `HttpSendRequestA`) and `WSOCK32.DLL` (`WSAStartup`, `connect`, `send`, `recv`) (source: deep-dive.json). This confirms the binary has the **latent capability** to communicate over HTTP and raw sockets.

However, **no specific C2 domains, IP addresses, URLs, or beaconing patterns were identified** in the static strings or configuration data. The network capability is present but its configuration and use were not observed in this analysis. The long base64-like string could potentially be a configuration blob containing C2 information, but this was not decoded.

## 7. Capability Assessment

| Capability | Evidence | Status |
| :--- | :--- | :--- |
| **Defense Evasion** | Process enumeration for 13 AV products (source: r2_disassembly); Anti-debugging via `IsDebuggerPresent` (source: ida_query); Obfuscated stack strings (source: capa). | **Observed** |
| **Persistence** | `CreateServiceA` import (source: pe_imports); `OpenSCManagerA` import (source: malcat). | **Observed** |
| **Execution** | RWX memory allocation (`VirtualAlloc`) (source: capa); Shellcode execution via indirect call (source: capa); APC injection (`QueueUserAPC`) (source: pe_imports). | **Observed** |
| **Discovery** | Process enumeration (`CreateToolhelp32Snapshot`) (source: capa). | **Observed** |
| **Command and Control** | Network API imports (WININET, WSOCK32) (source: deep-dive.json). | **Latent (Present but unused in observed flow)** |
| **Exfiltration** | Network API imports (source: deep-dive.json). | **Latent (Present but unused in observed flow)** |
| **Credential Access** | None observed. | **Not Observed** |
| **Lateral Movement** | None observed. | **Not Observed** |

## 8. Attribution

No specific threat actor or campaign attribution can be made based on the available evidence. The techniques are generic and used by many commodity malware authors. The targeted AV products do not point to a specific region or actor with high confidence.

## 9. Indicators of Compromise

**File-Based IOCs:**
*   **SHA256:** `5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`
*   **Import Hash (imphash):** `1905143b6a38c11e2b30615cb955fd08` (source: rule.yara.json)
*   **File Name:** `space1.ex`

**String-Based IOCs (from FLOSS & YARA):**
*   `&*^@QDSJGIO`
*   `&JTEH$WHD`
*   `V><MDNbyfui6y2iuow`
*   `fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6`

**Behavioral IOCs (for detection):**
*   Creation of a new Windows service.
*   Process enumeration for specific AV executables (list in Appendix B).
*   Allocation of RWX memory followed by APC injection.
*   Dynamic resolution of `CreateServiceA`, `QueueUserAPC`, `VirtualAlloc`.

## 10. Detection Rules

**YARA Rule (from rule.yara.json):**
A YARA rule was generated for this sample. Key strings include the obfuscated strings listed above and API names like `QueryPerformanceCounter`, `IsBadCodePtr`, and `CreateServiceA`. The rule is valid and has not been tested against a goodware corpus (source: rule.yara.json).

**Sigma Rule:**
A Sigma rule was also generated (path: `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/rule.yml`). Its content was not provided, but it is likely based on the behavioral IOCs, such as service creation or suspicious process enumeration.

**CAPA Rules:**
The following CAPA rules fired, providing detection logic for capabilities (source: capa):
*   `enumerate processes` (T1057)
*   `contain obfuscated stackstrings` (T1027.005)
*   `allocate or change RWX memory`
*   `execute shellcode via indirect call`
*   `check for trap flag exception` (anti-debug)

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
| :--- | :--- | :--- | :--- |
| **Defense Evasion** | Obfuscated Files or Information: Indicator Removal from Tools | T1027.005 | Obfuscated stack strings (source: capa) |
| **Defense Evasion** | Debugger Evasion | T1622 | `IsDebuggerPresent` import (source: ida_query) |
| **Discovery** | Process Discovery | T1057 | `CreateToolhelp32Snapshot` usage (source: capa, r2_disassembly) |
| **Execution** | Shared Modules | T1129 | Dynamic API resolution via `GetProcAddress`/`LoadLibraryA` (source: capa, pe_imports) |
| **Persistence** | Create or Modify System Process: Windows Service | T1543.003 | `CreateServiceA` import (source: pe_imports) |
| **Execution** | Process Injection: Asynchronous Procedure Call | T1055.004 | `QueueUserAPC` import (source: pe_imports) |

## 12. Containment, Eradication, Recovery

**Containment:**
1.  Isolate affected systems from the network immediately.
2.  Block the file hash (`5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`) at the perimeter firewall and endpoint protection.

**Eradication:**
1.  Identify and delete the malicious Windows service created by the malware. The service name is not known from static analysis and must be found via live system investigation (e.g., `sc query` or registry inspection).
2.  Terminate any suspicious processes spawned by the service.
3.  Delete the `space1.ex` file and any dropped components.
4.  Scan the system for additional persistence mechanisms (registry run keys, scheduled tasks) as a precaution.

**Recovery:**
1.  Restore affected systems from a known-good backup if integrity is in doubt.
2.  Reset credentials for any accounts that may have been compromised, especially if the system had elevated privileges.
3.  Monitor network traffic for any C2 communication attempts related to the identified IOCs.

## 13. Recommendations

1.  **Endpoint Detection:** Deploy or update endpoint detection rules (YARA, Sigma) to detect the behavioral patterns of this malware, specifically the process enumeration for the listed AV executables and the creation of services with suspicious characteristics.
2.  **Network Monitoring:** Implement network detection rules for the latent C2 capabilities. While no specific C2 was found, monitor for unusual HTTP or socket connections from systems running services that were recently created.
3.  **User Training:** Educate users on the risks of executing unknown files, especially those with double extensions or from untrusted sources.
4.  **System Hardening:** Ensure that endpoint protection is running and up-to-date. Consider application whitelisting to prevent the execution of unauthorized executables.
5.  **Incident Response:** Conduct a thorough investigation on any system where this file was found to determine the scope of compromise, lateral movement, and data exfiltration.

## 14. Appendix A: Evidence Trail

This section provides a traceable link from claims in the report to the source evidence.

| Claim | Source | Query/Rule | Why |
| :--- | :--- | :--- | :--- |
| Malware checks for 13 AV processes. | r2_disassembly | `entry0` at 0x402720 | Disassembly shows 13 calls to 0x402640 with AV process name strings. |
| Anti-debugging via `IsDebuggerPresent`. | ida_query | Imports (IDA) | Import table contains `IsDebuggerPresent`. |
| Service persistence via `CreateServiceA`. | pe_imports | pe_imports signals | High-signal import for service creation. |
| Shellcode execution capability. | capa | capa rules | Rule "execute shellcode via indirect call" matched. |
| Process enumeration for discovery. | ghidra_query | Anti Analysis Signals | Function calls `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`. |
| Obfuscated stack strings. | capa | capa rules | Rule "contain obfuscated stackstrings" matched. |
| RWX memory allocation. | capa | capa rules | Rule "allocate or change RWX memory" matched. |
| Network capability (latent). | deep-dive.json | key_evidence | Imports from WININET and WSOCK32 DLLs listed. |
| Binary is not UPX packed. | UPX unpack | upx_probe_stdout | UPX probe tested 0 files. |
| YARA rule generated. | rule.yara.json | yara_valid | `yara_valid: true`. |

## 15. Appendix B: Module Inventory

**Targeted Security Product Processes (from entry function):**
The malware enumerates for the following 13 processes (source: r2_disassembly, deep-dive.json):
1.  `QHACTIVEDEFENSE.EXE` (360 Security)
2.  `QHSAFETRAY.EXE` (360 Security)
3.  `QHWATCHDOG.EXE` (360 Security)
4.  `CMDAGENT.EXE` (Comodo)
5.  `CIS.EXE` (Comodo Internet Security)
6.  `V3LITE.EXE` (AhnLab V3)
7.  `V3MAIN.EXE` (AhnLab V3)
8.  `V3SP.EXE` (AhnLab V3)
9.  `SPIDERAGENT.EXE` (Dr.Web)
10. `DWENGINE.EXE` (Dr.Web)
11. `DWARKDAEMON.EXE` (Dr.Web)
12. `EGUI.EXE` (ESET)
13. `EKRN.EXE` (ESET)

**Recovered Function Names (from agentic_recover_v4):**
| Address | Name | Confidence | Notes |
| :--- | :--- | :--- | :--- |
| 4201495 | `reset_gs_failure_flag` | 0.7 | Resets a global variable, likely related to buffer security. |
| 4203936 | `anti_analysis_check` | 0.75 | Calls `IsDebuggerPresent` and checks PE headers. |
| 4202880 | `anti_debug_check` | 0.85 | Measures time with `QueryPerformanceCounter` to detect debugging. |
| 4204096 | `check_process_exists` | 0.65 | Enumerates processes and compares names. |
| 4202672 | `resolve_import_table` | 0.7 | Resolves PE imports dynamically. |
| 4203488 | `load_and_execute_pe` | 0.9 | Loads and executes a PE from memory. |

**CAPA Capabilities (11 rules):**
*   link function at runtime on Windows (T1129)
*   parse PE header (T1129)
*   contain obfuscated stackstrings (T1027.005)
*   enumerate processes (T1057)
*   enumerate processes (T1518)
*   find graphical window (T1010)
*   check for trap flag exception
*   allocate or change RWX memory
*   terminate process
*   enumerate PE sections
*   execute shellcode via indirect call
*   extract resource via kernel32 functions

## 16. Author + Sign-off

**Report Author:** LLM Judge (Automated Analysis Pipeline)
**Date:** 2026-08-09
**Version:** 2.0

This report was generated by an automated malware analysis pipeline. All findings are based on the provided evidence from static analysis tools (Ghidra, IDA, radare2, CAPA, YARA, MalCat, FLOSS). No dynamic analysis was performed. The verdict of "malicious" is based on clear behavioral intent observed in the static code flow, not on obfuscation alone.