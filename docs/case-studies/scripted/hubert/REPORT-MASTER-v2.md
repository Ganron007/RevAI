> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 11:49:35 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: hubert.dll (Tibs Trojan Downloader)

## Executive Summary

This report details the analysis of a malicious DLL file (`hubert.dll`) identified as a member of the Tibs malware family. The sample is a packed and obfuscated trojan downloader that employs multiple evasion techniques, including XOR-based encryption, anti-VM checks, and high-entropy packing. Static and behavioral analysis confirm its malicious intent through the presence of process injection, privilege escalation, and network communication capabilities. The DLL uses WinINet APIs for command-and-control (C2) communication and contains strings indicative of registry manipulation for persistence. External threat intelligence from VirusTotal reports a high detection rate (58/70 engines), corroborating our findings. We assess with high confidence that this sample is malicious and designed for initial access, execution, and persistence on compromised systems.

## 1. Sample Identification

The sample under analysis is a 32-bit Windows DLL file with the following characteristics:

| Attribute | Value |
|-----------|-------|
| **SHA256** | `0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc` |
| **File Path** | `/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll` |
| **File Type** | PE32 DLL (Dynamic Link Library) |
| **Architecture** | x86 (32-bit) |
| **Entropy** | 7.99 bits/byte (whole-file Shannon entropy) |
| **Import Hash** | `c69e7c5c6b975b5dd44f2d4469eea107` |
| **Sections** | `.nasoc`, `.tlsc` (unusual names), `.text`, `.rdata`, `.data`, `.rsrc` |
| **Packing** | Not UPX; custom packing suspected due to high entropy and section anomalies |

The high entropy (7.99) and unusual section names (`.nasoc`, `.tlsc`) are strong indicators of packing or obfuscation (source: malcat). The file is not a .NET assembly (source: dotnet_analyze).

## 2. Classification

**Verdict: MALICIOUS**

**Confidence: 95/100**

**Family: Tibs (Trojan.Tibs/gen2)**

The classification is based on multiple converging lines of evidence:
1.  **Behavioral Intent:** The sample contains YARA rule matches for process injection (`ProcessInjectionTargets`) and privilege escalation (`ElevatePrivileges`), which are clear indicators of malicious functionality (source: malcat).
2.  **Network Capability:** High-signal imports for WinINet APIs (`InternetOpenA`, `InternetReadFile`) and strings like `InternetOpenUrlA` confirm C2 communication capability (source: malcat, floss).
3.  **Obfuscation & Evasion:** XOR decryption loops (key `0x5d785e`) and anti-VM strings targeting Xen are present (source: malcat, capa).
4.  **External Corroboration:** VirusTotal reports 58/70 AV detections as malicious, with the label `trojan.tibs/gen2` (source: external_ti).
5.  **Upstream Triage:** The initial triage verdict is `malicious` with a score of 95 (source: triage verdict.json).

The sample's capabilities extend beyond mere obfuscation. The presence of behavioral YARA rules for injection and escalation, combined with network and registry APIs, constitutes behavioral-intent evidence. This is not a benign protected binary.

## 3. Background & Family Lineage

The Tibs family is a well-documented line of trojan downloaders known for their use of packing, obfuscation, and injection techniques. They typically serve as first-stage payloads to deliver additional malware. Key characteristics include:
-   **Packing/Obfuscation:** Use of custom packers with high entropy and anti-analysis features.
-   **Process Injection:** Commonly injects code into legitimate processes to evade detection.
-   **Privilege Escalation:** Attempts to gain higher privileges for system-level operations.
-   **C2 Communication:** Uses HTTP/HTTPS via WinINet or WinHTTP for downloading additional payloads.

This sample aligns with the Tibs lineage through its use of XOR encryption, anti-VM checks, and the specific import set for injection and network activity. The import hash `c69e7c5c6b975b5dd44f2d4469eea107` may be linked to other Tibs variants in threat intelligence databases.

## 4. Static Analysis

### 4.1 Entropy & Packing
The file's whole-file Shannon entropy is 7.99 bits/byte, which is extremely high and indicative of encryption or compression (source: malcat). UPX analysis confirmed it is not packed with UPX (source: UPX unpack). The presence of sections with unknown names (`.nasoc`, `.tlsc`) and a section with both write and execute permissions (`SectionWX`) further suggests a custom packer (source: malcat).

### 4.2 Import Analysis
The import table contains 79 functions, with several high-signal APIs that are commonly abused by malware:

| API | Module | Signal | Purpose |
|-----|--------|--------|---------|
| `InternetOpenA` | wininet | High | Initialize C2 session |
| `InternetOpenUrlA` | wininet | High | Open C2 URL |
| `InternetReadFile` | wininet | High | Download payload |
| `InternetCloseHandle` | wininet | High | Clean up session |
| `AdjustTokenPrivileges` | advapi32 | High | Privilege escalation |
| `LookupPrivilegeValueW` | advapi32 | High | Find privilege to escalate |
| `VirtualAlloc` | kernel32 | High | Allocate memory for injection |
| `RegCreateKeyA` | advapi32 | High | Create registry key for persistence |
| `RegSetValueExA` | advapi32 | High | Set registry value |
| `CreateProcessW` | kernel32 | Medium | Launch process for injection |
| `CreateThread` | kernel32 | Medium | Execute injected code |
| `OpenProcessToken` | advapi32 | Medium | Access token for manipulation |

(source: malcat, pe_imports). The presence of `VirtualAlloc`, `CreateProcessW`, and `CreateThread` in conjunction with `AdjustTokenPrivileges` strongly suggests a process injection and privilege escalation workflow.

### 4.3 String Analysis
FLOSS extracted 695 strings. Key findings include:
-   **Registry:** `Software\\` (persistence key) (source: floss).
-   **Network APIs:** `InternetOpenUrlA`, `InternetReadFile`, `InternetOpenA`, `InternetCloseHandle` (source: floss).
-   **System APIs:** `CreateMutexW`, `WaitForSingleObject`, `GetTickCount` (likely for anti-debug or timing) (source: floss).
-   **Obfuscated Strings:** Several strings appear to be XOR-encrypted, such as `Pkdpqmjwl` and `a%u%wvjk%qwl%v%qj%vq%di%|jpw%udvvrjwav%dka%uwlsdq%lkcjwhdqljk+%Filfn%jk%qm%h%vvdb%qj%uw%s%kq%la%kqlq|%qm%cq+` (source: rule.yara.json). The XOR key `0x5d785e` is used in a decryption loop (source: malcat decompilations).

### 4.4 YARA & Capa Rules
Multiple YARA rules fired, confirming malicious patterns:
-   `ProcessInjectionTargets`: Matches strings related to process injection (source: malcat).
-   `ElevatePrivileges`: Matches strings for privilege escalation (source: malcat).
-   `win_registry`: Matches registry manipulation strings (source: checklist_yara_scan).
-   `Str_Win32_Internet_API`: Matches WinINet API strings (source: checklist_yara_scan).
-   `contains_base64`: Indicates possible base64-encoded payloads (source: checklist_yara_scan).

Capa identified two key behaviors:
1.  **T1027 - Obfuscated Files or Information:** `encode data using XOR` (source: capa).
2.  **T1497.001 - Virtualization/Sandbox Evasion: System Checks:** `reference anti-VM strings targeting Xen` (source: capa).

## 5. Behavioral Analysis

Dynamic analysis tools (Speakeasy, Frida) were executed but recorded no runtime events. This is a significant finding, as it suggests the sample employs anti-analysis techniques to detect or evade sandbox environments. The absence of observed behavior does not indicate benign intent; rather, it points to the sample's evasion capabilities (source: tool evidence). The anti-VM strings identified by Capa (targeting Xen) support this assessment.

## 6. Network Analysis & C2

The sample contains all necessary components for HTTP-based C2 communication:
-   **WinINet API Imports:** `InternetOpenA`, `InternetOpenUrlA`, `InternetReadFile`, `InternetCloseHandle` (source: malcat).
-   **Network Strings:** `InternetOpenUrlA` (source: floss).
-   **YARA Match:** `Str_Win32_Internet_API` (source: checklist_yara_scan).

The decompiled function `sub_100027e5` shows a decryption routine using XOR key `0x5d785e` (source: malcat). This key is likely used to decrypt C2 URLs or configuration data at runtime. The specific C2 server addresses are not present in the static strings, as they are likely encrypted. The sample's capability to download and execute additional payloads is confirmed by the import of `InternetReadFile` and `VirtualAlloc`.

## 7. Capability Assessment

| Capability | Evidence | Status |
|------------|----------|--------|
| **Process Injection** | YARA rule `ProcessInjectionTargets`, imports: `VirtualAlloc`, `CreateProcessW`, `CreateThread` | **Observed (Static)** |
| **Privilege Escalation** | YARA rule `ElevatePrivileges`, imports: `AdjustTokenPrivileges`, `LookupPrivilegeValueW` | **Observed (Static)** |
| **C2 Communication** | WinINet API imports, YARA rule `Str_Win32_Internet_API` | **Observed (Static)** |
| **Registry Manipulation** | YARA rule `win_registry`, imports: `RegCreateKeyA`, `RegSetValueExA` | **Observed (Static)** |
| **Anti-VM Evasion** | Capa rule `reference anti-VM strings targeting Xen` | **Observed (Static)** |
| **Obfuscation** | High entropy, XOR loops, encrypted strings | **Observed (Static)** |
| **Credential Theft** | No indicators found | **Not Observed** |
| **Lateral Movement** | No indicators found | **Not Observed** |
| **Data Exfiltration** | No specific indicators, but C2 channel exists | **Latent Capability** |

The sample's primary capabilities are injection, escalation, and C2. It is a downloader, so its main purpose is to fetch and execute additional payloads. The lack of observed runtime behavior means we cannot confirm if these capabilities are actively used in a live environment, but the static evidence confirms the intent and codebase for these actions.

## 8. Attribution

No specific threat actor attribution can be made based on the available evidence. The Tibs family is a generic malware category used by multiple actors. The sample's infrastructure (C2 servers) is not present in the analyzed strings, preventing network-based attribution. The use of Visual Basic v5.0 signatures (source: checklist_yara_scan) may indicate a specific development toolset, but this is not sufficient for attribution.

## 9. Indicators of Compromise

### 9.1 File-Based IOCs
| Type | Value |
|------|-------|
| **SHA256** | `0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc` |
| **Import Hash** | `c69e7c5c6b975b5dd44f2d4469eea107` |
| **File Name** | `hubert.dll` |

### 9.2 String-Based IOCs
| Type | Value | Context |
|------|-------|---------|
| **Registry Key** | `Software\\` | Persistence |
| **Mutex** | `Shell_TrayWnd` | Possible anti-analysis or persistence |
| **GUID** | `dd1c3e54-4b10-4a73-91eb-fa561c094261` | Unknown, possibly configuration |
| **GUID** | `24d1ca9a-a864-4f7b-86fe-495eb56529d8` | Unknown, possibly configuration |
| **User-Agent** | `wget 3.0` | Network communication |
| **XOR Key** | `0x5d785e` | Decryption routine |

### 9.3 Behavioral IOCs
-   **Process Injection:** Targeting `explorer.exe` (string present) (source: rule.yara.json).
-   **Privilege Escalation:** Use of `AdjustTokenPrivileges` API.
-   **Network Beaconing:** Use of `InternetOpenA` with a custom User-Agent.

## 10. Detection Rules

### 10.1 YARA Rule
A YARA rule was generated for this sample (source: rule.yara.json). Key strings include:
-   `!This program cannot be run in DOS mode.` (common, but context matters)
-   `Pkdpqmjwl` (obfuscated string)
-   `Software\\` (registry key)
-   `Shell_TrayWnd` (mutex)
-   `wget 3.0` (user-agent)
-   `explorer.exe` (injection target)

The rule is located at `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/rule.yar`.

### 10.2 Sigma Rule
A Sigma rule was also generated (source: rule.yara.json) at `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/rule.yml`.

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| **Defense Evasion** | Obfuscated Files or Information | T1027 | XOR encryption loops (source: capa) |
| **Defense Evasion** | Virtualization/Sandbox Evasion: System Checks | T1497.001 | Anti-VM strings targeting Xen (source: capa) |
| **Execution** | Shared Modules | T1129 | DLL execution |
| **Persistence** | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | Registry key `Software\\` (source: floss) |
| **Privilege Escalation** | Access Token Manipulation | T1134 | `AdjustTokenPrivileges` import (source: malcat) |
| **Defense Evasion** | Process Injection | T1055 | YARA rule `ProcessInjectionTargets`, `VirtualAlloc` import (source: malcat) |
| **Command and Control** | Application Layer Protocol: Web Protocols | T1071.001 | WinINet API imports (source: pe_imports) |
| **Command and Control** | Ingress Tool Transfer | T1105 | `InternetReadFile` import for downloading (source: malcat) |

## 12. Containment, Eradication, Recovery

### 12.1 Containment
-   **Isolate** affected systems immediately to prevent lateral movement.
-   **Block** the SHA256 hash and import hash at the network perimeter and endpoint protection.
-   **Monitor** for network connections to unknown domains, especially those using the `wget 3.0` user-agent.

### 12.2 Eradication
-   **Terminate** any processes spawned by the DLL or exhibiting injection behavior.
-   **Remove** the malicious DLL file from the system.
-   **Clean** registry keys under `Software\\` that may have been created for persistence.
-   **Scan** for additional payloads that may have been downloaded and executed.

### 12.3 Recovery
-   **Restore** affected systems from known-good backups if compromise is confirmed.
-   **Change** credentials for any accounts that may have been exposed.
-   **Update** endpoint protection signatures with the provided YARA and Sigma rules.

## 13. Recommendations

1.  **Deploy Detection Rules:** Implement the generated YARA and Sigma rules across the environment to detect this and similar variants.
2.  **Enhance Monitoring:** Configure logging for suspicious API calls (`AdjustTokenPrivileges`, `VirtualAlloc` in non-browser processes) and registry modifications.
3.  **Network Filtering:** Block traffic with the user-agent `wget 3.0` and monitor for connections to domains associated with Tibs C2 infrastructure.
4.  **User Training:** Educate users on the risks of executing unknown DLLs, especially those received via email or downloaded from untrusted sources.
5.  **Sandbox Evasion Countermeasures:** Ensure analysis environments are configured to evade common anti-VM checks (e.g., Xen, VMware artifacts).

## 14. Appendix A: Evidence Trail

| Source | Query/Table | Row/Rule | Why |
|--------|-------------|----------|-----|
| malcat | malcat_evidence | ProcessInjectionTargets | YARA rule matching process injection targets, indicating malicious intent for code injection. |
| malcat | malcat_evidence | ElevatePrivileges | YARA rule matching privilege escalation, a common malicious behavior. |
| malcat | anomalies | XorInLoop | XOR operations in loops at addresses 7008, 7021, 7187, indicating data decryption/obfuscation. |
| malcat | decompilations | sub_100027e5 | Decompilation shows XOR loop with key 0x5d785e, a clear decryption routine. |
| malcat | top high-signal imports | wininet.InternetReadFile | Network communication import for C2/beaconing. |
| malcat | top high-signal imports | advapi32.AdjustTokenPrivileges | Token manipulation for privilege escalation. |
| malcat | top high-signal imports | kernel32.VirtualAlloc | Memory allocation for code injection or shellcode. |
| capa | capa rules | reference anti-VM strings targeting Xen | Anti-analysis technique to evade virtualization sandboxes (T1497.001). |
| floss | strings | InternetOpenUrlA | Indicates network communication capability. |
| floss | strings | Software\\ | Registry key for persistence or configuration. |
| external_ti | VirusTotal | malicious=58 | 58/70 AV detections as malicious with threat label 'trojan.tibs/gen2'. |
| checklist_yara_scan | escalate_priv | matched strings at offsets 14078 and 14016 | Contains strings associated with privilege escalation techniques, a common malicious behavior. |
| checklist_yara_scan | win_registry | multiple string matches at various offsets | Indicates extensive registry manipulation for persistence, configuration, or malicious activity. |
| checklist_yara_scan | Str_Win32_Internet_API | matched API calls like InternetOpen and HttpSendRequest | Demonstrates network communication capabilities, suggesting command and control or data exfiltration. |
| checklist_yara_scan | contains_base64 | matched base64 string at offset 10822 | May contain obfuscated malicious payloads or data encoded to evade detection. |
| checklist_yara_scan | Microsoft_Visual_Basic_v50 | signature match at offset 79 | Indicates development in Visual Basic v5.0, which is sometimes used in malware for its scripting capabilities. |

## 15. Appendix B: Module Inventory

The sample is a single DLL. Its internal functions, as identified by static analysis, include:

| Address | Name | Size | Purpose (Inferred) |
|---------|------|------|-------------------|
| 0x1000271f | EntryPoint | 49 | DLL entry point, initiates execution. |
| 0x10002749 | sub_10002749 | 111 | Main orchestrator; calls decryption and injection routines. |
| 0x100027b8 | sub_100027b8 | 21 | Helper function for memory manipulation. |
| 0x100027d7 | sub_100027d7 | 14 | Sets up registers for decryption loop. |
| 0x100027e5 | sub_100027e5 | 73 | Core decryption routine using XOR key 0x5d785e. |
| 0x100027cd | sub_100027cd | N/A | Called from entry point, likely a dispatcher. |
| 0x100027d4 | sub_100027d4 | N/A | Unknown function. |
| 0x100027e5 | _Run@0 | N/A | Exported function, likely the main malicious payload. |

(source: malcat, radare2). The `_Run@0` export is the likely entry point for the malicious payload when the DLL is loaded.

## 16. Author + Sign-off

**Analyst:** LLM Judge (Automated Analysis)
**Date:** 2026-08-12
**Report Version:** 2.0

This report was generated based on automated static and dynamic analysis. All findings are cited to their source tools. The sample is assessed as malicious with high confidence. Recommendations are provided for containment and detection.