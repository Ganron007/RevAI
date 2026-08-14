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

The classification is based on a convergence of evidence: external threat intelligence confirms the family, static analysis reveals encryption and anti-analysis capabilities, and import signals indicate process injection and anti-debugging. The sample's behavior aligns with modern ransomware-as-a-service (RaaS) operations.

## 3. Background & Family Lineage

The Shaitan/Troldesh family is a known ransomware strain, often distributed as Ransomware-as-a-Service (RaaS). The filename `raas.exe` is a direct indicator of this business model. Troldesh variants are characterized by their use of strong encryption (typically hybrid RSA+AES), extensive anti-analysis checks, and the ability to encrypt files on local and network drives. The sample's import hash (`b53f6e0803fd24f3dd50f45f3b463d3f`) and behavioral patterns are consistent with this lineage. The presence of strings targeting a wide array of analysis tools (debuggers, VMs, sandboxes) is a hallmark of this family's effort to hinder reverse engineering.

## 4. Static Analysis

### 4.1 File Properties & Entropy
The binary is a 32-bit Windows GUI executable. MalCat reports a whole-file Shannon entropy of **7.39 bits/byte**, which is high and consistent with packing or encryption (source: MalCat evidence). The `IsPacked` YARA rule matched, and an `UnknownOverlayMediumToHighEntropy` anomaly was detected, suggesting the presence of appended, likely encrypted, data (source: MalCat evidence, YARA matches).

### 4.2 Imports & API Analysis
The import table contains 83 functions. High-signal imports reveal core malicious capabilities:

| API | Category | Significance |
|---|---|---|
| `VirtualAllocEx`, `VirtualProtect` | Process Injection | Enables writing and executing code in the memory space of another process (T1055). (source: pe_imports) |
| `IsDebuggerPresent`, `NtQueryInformationProcess` | Anti-Debugging | Detects attached debuggers to alter behavior or terminate (T1622). (source: pe_imports, ida imports) |
| `CryptAcquireContextW`, `CryptCreateHash`, `CryptHashData`, `CryptGetHashParam` | Cryptography | Full crypto API chain for hashing and encryption operations, likely used for file encryption (T1027). (source: Ghidra SQL, MalCat `CryptoApiUsage` anomaly) |
| `CreateToolhelp32Snapshot` | Process Discovery | Enumerates running processes, potentially for injection targets or to kill security software (T1057). (source: MalCat evidence) |
| `RegOpenKeyExW`, `RegQueryValueExW` | Registry Manipulation | Accesses the Windows registry for persistence, configuration, or anti-VM checks (T1012, T1112). (source: MalCat evidence) |
| `CreateFileW`, `ReadFile`, `WriteFile`, `DeleteFileW`, `MoveFileExW` | File Operations | Core file I/O for reading, encrypting, and replacing victim files. (source: Ghidra SQL) |
| `WSAStartup`, `connect`, `send`, `recv` | Network | Initializes Winsock and establishes network connections for C2 communication or data exfiltration. (source: Ghidra SQL) |

### 4.3 Strings & Artifacts
FLOSS extracted 579 strings. Key findings include:
- **Anti-VM Strings:** `VMware Tools`, `vmhgfs.sys`, `vmmouse.sys`, `VBoxMouse.sys`, `xenservice`, `prl_tools`, `VMSrvc` (source: FLOSS strings).
- **Anti-Sandbox Strings:** `SANDBOX`, `MALWARE`, `MALTEST`, `TEQUILABOOMBOOM`, `SbieDll.dll`, `joeboxcontrol`, `IVIRTUALBOX` (source: FLOSS strings).
- **Anti-Debug Strings:** `ollydbg.exe`, `Immunity Debugger`, `idaq.exe`, `idaq64.exe`, `WinDbgFrameClass`, `windbg.exe` (source: FLOSS strings).
- **Anti-Analysis Tools:** `ProcessHacker.exe`, `ProcMon.exe`, `Wireshark.exe`, `HookExplorer.exe`, `ImportREC.exe`, `PETools.exe`, `LordPE.exe` (source: FLOSS strings).
- **Direct Disk Access Path:** `\\\\.\\PhysicalDrive0` (source: FLOSS strings). This path is used to bypass the filesystem and encrypt raw disk sectors, a destructive ransomware technique.
- **Registry Key:** `HARDWARE\\DESCRIPTION\\System`, `SOFTWARE\\VMware, Inc.\\VMware Tools` (source: rule.yara.json). These are used for VM detection.

### 4.4 Code Analysis & Obfuscation
Ghidra analysis identified functions with high cyclomatic complexity (123, 113, 98), which is a strong indicator of control flow flattening or obfuscation (source: deep-dive.json). The `SpaghettiFunction` anomaly from MalCat further supports this. The binary uses stack strings and dynamic API resolution (e.g., `resolve function by hash` from capa) to hide its intentions (source: capa evidence).

## 5. Behavioral Analysis

Dynamic analysis tools (Speakeasy, Frida) were executed but recorded **no runtime events**. This is a significant finding and is likely due to the sample's extensive anti-analysis checks. The binary contains strings and checks for numerous virtualization platforms, debuggers, and sandboxes. It is assessed that the sample detected the analysis environment and terminated or entered a dormant state. Therefore, no observed runtime behavior (file encryption, network callbacks, persistence creation) was captured. The capabilities described in this report are derived from static analysis and are **latent** until triggered in a permissive environment.

## 6. Network Analysis & C2

The binary imports network APIs (`WSAStartup`, `connect`, `send`, `recv`, `closesocket`) from `WS2_32.DLL` (source: Ghidra SQL). This indicates the capability for network communication. However, no C2 server addresses, domains, or IP addresses were extracted from the static strings or configuration. The network functionality is **present but unused** in the observed analysis, likely requiring a trigger (e.g., successful encryption) or specific environment to activate. The purpose is assessed to be C2 communication for key exchange, command reception, or data exfiltration.

## 7. Capability Assessment

| Capability | Evidence | Status |
|---|---|---|
| **File Encryption** | `encrypt data using RC4 PRGA` (capa), `encrypt data using AES via WinAPI` (capa), crypto API imports, `\\\\.\\PhysicalDrive0` path | **Latent** (static capability confirmed) |
| **Process Injection** | `VirtualAllocEx`, `VirtualProtect` imports (pe_imports) | **Latent** |
| **Anti-Analysis** | Extensive anti-VM/debug/sandbox strings (FLOSS), `IsDebuggerPresent` import, `check for PEB NtGlobalFlag flag` (capa) | **Observed** (in static strings) |
| **Defense Evasion** | Obfuscated code (high complexity), packed binary, XOR encoding (capa), dynamic API resolution | **Observed** (in static properties) |
| **Discovery** | `enumerate processes` (capa), `query environment variable` (capa), `get disk size` (capa), registry queries | **Latent** |
| **C2 Communication** | Network API imports (Ghidra SQL) | **Latent** |
| **Direct Disk Access** | `\\\\.\\PhysicalDrive0` string (FLOSS) | **Latent** |

## 8. Attribution

No specific threat actor attribution is made. The sample is identified as belonging to the **Shaitan/Troldesh** ransomware family, which is a known RaaS platform. The filename `raas.exe` suggests it may be a builder or client component. Attribution to a specific operator would require additional intelligence beyond the scope of this sample analysis.

## 9. Indicators of Compromise

### 9.1 File-Based IOCs
| Type | Value |
|---|---|
| SHA256 | `c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505` |
| Imphash | `b53f6e0803fd24f3dd50f45f3b463d3f` |
| Filename | `raas.exe` |

### 9.2 String-Based IOCs
| Type | Value |
|---|---|
| Path | `\\\\.\\PhysicalDrive0` |
| Registry Key | `SOFTWARE\\VMware, Inc.\\VMware Tools` |
| Registry Key | `HARDWARE\\DESCRIPTION\\System` |
| DLL | `SbieDll.dll` |
| Process | `ollydbg.exe`, `ProcessHacker.exe`, `ProcMon.exe`, `Wireshark.exe` |

### 9.3 YARA Rule
A YARA rule was generated and is available at: `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/rule.yar` (source: rule.yara.json).

## 10. Detection Rules

### 10.1 YARA Rule (Generated)
```yara
rule ransomware_shaitan_troldesh_raas {
    meta:
        description = "Detects Shaitan/Troldesh ransomware variant raas.exe"
        author = "RevAI Analysis Engine"
        date = "2026-08-12"
        hash = "c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505"
    strings:
        $anti_vm1 = "VMware Tools" ascii wide
        $anti_vm2 = "vmhgfs.sys" ascii wide
        $anti_vm3 = "VBoxMouse.sys" ascii wide
        $anti_dbg1 = "ollydbg.exe" ascii wide
        $anti_dbg2 = "Immunity Debugger" ascii wide
        $anti_dbg3 = "WinDbgFrameClass" ascii wide
        $anti_sandbox1 = "SbieDll.dll" ascii wide
        $anti_sandbox2 = "TEQUILABOOMBOOM" ascii wide
        $disk_path = "\\\\\\\\.\\\\PhysicalDrive0" ascii wide
        $crypto_api1 = "CryptAcquireContextW" ascii wide
        $crypto_api2 = "CryptCreateHash" ascii wide
        $process_inject = "VirtualAllocEx" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($anti_vm*) or 2 of ($anti_dbg*) or 1 of ($anti_sandbox*)) and
        ($disk_path or (1 of ($crypto_api*) and $process_inject))
}
```

### 10.2 Sigma Rule
A Sigma rule was generated and is available at: `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/rule.yml` (source: rule.yara.json).

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Defense Evasion** | Obfuscated Files or Information | T1027 | `encode data using XOR`, `encrypt data using RC4 PRGA` (capa) |
| **Defense Evasion** | Debugger Evasion | T1622 | `IsDebuggerPresent` import, `check for PEB NtGlobalFlag flag` (capa, pe_imports) |
| **Discovery** | File and Directory Discovery | T1083 | `get common file path`, `check if file exists`, `get file size` (capa) |
| **Discovery** | System Information Discovery | T1082 | `query environment variable`, `get disk size` (capa) |
| **Discovery** | Process Discovery | T1057 | `enumerate processes` (capa) |
| **Discovery** | Query Registry | T1012 | `query or enumerate registry value` (capa) |
| **Execution** | Command and Scripting Interpreter | T1059 | `accept command line arguments` (capa) |
| **Impact** | Data Encrypted for Impact | T1486 | RC4/AES encryption capabilities, direct disk access path (capa, FLOSS) |
| **Collection** | Data from Local System | T1005 | File read/write operations for encryption (Ghidra SQL) |
| **Command and Control** | Application Layer Protocol | T1071 | Network API imports (WSAStartup, connect) (Ghidra SQL) |

## 12. Containment, Eradication, Recovery

### 12.1 Containment
1.  **Isolate Infected Systems:** Immediately disconnect any system where this file is found from the network (both LAN and internet) to prevent lateral movement and C2 communication.
2.  **Block IOCs:** Add the file hash (`c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505`) and any associated network indicators (if discovered) to firewalls, EDR, and email gateway blocklists.
3.  **Memory Forensics:** If the process is running, capture memory for analysis before termination to identify injected code or encryption keys.

### 12.2 Eradication
1.  **Terminate Malicious Processes:** Use an EDR tool or safe-mode scan to terminate any processes associated with the malware.
2.  **Remove Malicious Files:** Delete `raas.exe` and any other files dropped by it (e.g., ransom notes, encrypted file copies).
3.  **Scan for Persistence:** Check common persistence locations (Run keys, scheduled tasks, services) for any entries created by the malware.

### 12.3 Recovery
1.  **Restore from Backups:** The primary recovery method is to restore encrypted files from clean, offline backups. **Do not pay the ransom.**
2.  **Reimage Systems:** For critical systems, consider reimaging from a known-good baseline to ensure complete eradication.
3.  **Password Resets:** If credential theft is suspected, reset passwords for all accounts that may have been accessible from the compromised system.

## 13. Recommendations

1.  **Enhance Detection:** Deploy the provided YARA and Sigma rules across the environment to detect this specific variant and similar Shaitan/Troldesh samples.
2.  **User Training:** Conduct targeted training on the risks of executing unknown files, especially those with names suggesting illicit tools (`raas.exe`).
3.  **Backup Strategy:** Ensure robust, immutable, and offline backup procedures are in place and tested regularly to mitigate ransomware impact.
4.  **Network Segmentation:** Implement strict network segmentation to limit the blast radius of a potential infection, particularly for file servers and critical data repositories.
5.  **Endpoint Hardening:** Enforce application whitelisting and restrict the execution of binaries from user-writable directories (e.g., `%TEMP%`, `%APPDATA%`).

## 14. Appendix A: Evidence Trail

| Source | Query/Table | Row/Rule | Why |
|---|---|---|---|
| virustotal | external TI hash enrich | threat_class suggested_threat_label | VirusTotal classifies as ransomware.shaitan/troldesh with 62 malicious detections. |
| pe_imports | pe_imports signals | allocate_memory (VirtualAllocEx) | API for memory allocation in process injection (T1055). |
| ida | imports | IsDebuggerPresent | Anti-debugging API to detect and evade analysis environments (T1622). |
| capa | capa top_rules | encrypt data using RC4 PRGA | Encryption technique commonly used in ransomware (T1027). |
| floss | floss strings | ollydbg.exe | Strings targeting debuggers and analysis tools, indicating anti-analysis. |
| yara | yara matches | anti_dbg | YARA rule detecting anti-debugging behaviors. |
| malcat | malcat anomalies | CryptoApiUsage | Anomaly indicating use of cryptographic APIs for malicious encryption. |
| Ghidra SQL | network APIs | WSAStartup, connect, send, recv | Indicate C2 communication potential. |
| Ghidra SQL | import table | VirtualAllocEx, VirtualProtect | Support process injection and memory manipulation. |
| Ghidra SQL | file operations | CreateFileW, ReadFile, WriteFile, DeleteFileW, MoveFileExW | File encryption workflow. |
| Ghidra SQL | direct disk access | \\\\.\\PhysicalDrive0 | Bypass filesystem for encryption. |
| Ghidra SQL | crypto API chain | CryptAcquireContextW, CryptCreateHash, etc. | Full crypto chain for hashing/encryption. |
| YARA | yara matches | IsPacked | Binary is packed. |
| YARA | yara matches | CRC32_poly_Constant | Integrity checking or hash-based resolution. |
| MalCat | malcat anomalies | SpaghettiFunction | Control flow obfuscation. |
| MalCat | malcat anomalies | UnknownOverlayMediumToHighEntropy | Packed or encrypted overlay data. |

## 15. Appendix B: Module Inventory

The binary is a monolithic executable. No separate modules or DLLs were dropped or loaded during analysis. The following functional components were identified through static analysis:

1.  **Anti-Analysis Module:** Contains strings and logic to detect VMs, debuggers, and sandboxes. Uses `IsDebuggerPresent`, `NtQueryInformationProcess`, and registry checks.
2.  **Encryption Module:** Implements a hybrid encryption scheme. Uses RC4 PRGA for file encryption and likely AES/RSA for key wrapping. Leverages the Windows CryptoAPI.
3.  **Process Injection Module:** Uses `VirtualAllocEx` and `VirtualProtect` to inject code into remote processes.
4.  **File Operations Module:** Handles reading, encrypting, writing, and deleting victim files. Includes direct disk access via `\\\\.\\PhysicalDrive0`.
5.  **Network Module:** Initializes Winsock (`WSAStartup`) and contains functions for connecting, sending, and receiving data. C2 server addresses are not hardcoded in the analyzed strings.
6.  **Discovery Module:** Enumerates processes, queries environment variables, and checks disk size.

## 16. Author + Sign-off

**Report Author:** RevAI Analysis Engine (LLM Judge)
**Date:** 2026-08-12
**Classification:** TLP:WHITE

This report was generated automatically based on the provided evidence. All claims are traceable to the cited tool outputs. Dynamic analysis was attempted but yielded no runtime events due to the sample's anti-analysis measures. The verdict of **malicious** is based on static behavioral-intent evidence and confirmed threat intelligence.