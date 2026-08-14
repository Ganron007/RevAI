> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 05:11:37 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Locky Ransomware Analysis Report

## Executive Summary

This report details the analysis of a 32-bit Windows executable (`svchost.exe`) identified as Locky ransomware. The sample exhibits classic ransomware behavior: it encrypts victim files using the Windows CryptoAPI, appends the `.locky` extension, drops a ransom note (`\_Locky_recover_instructions.txt`), and deletes Volume Shadow Copies to prevent system recovery. It communicates with six hardcoded command-and-control (C2) IP addresses over HTTP to report encryption statistics. The analysis is based on static analysis, YARA rule matching, and decompilation. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events. The sample is assessed with high confidence to be malicious Locky ransomware.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| SHA256 | `28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb` |
| File Name | `svchost.exe` |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Architecture | x86 (32-bit) |
| Entropy | 6.13 bits/byte (whole-file Shannon entropy) |
| Packed | No (UPX probe returned 0 files tested) |
| .NET | Not a .NET assembly |
| Project | malware |

The sample is a standard 32-bit Windows executable with a GUI subsystem. The entropy of 6.13 bits/byte is within the normal range for compiled code and does not indicate packing or encryption of the entire file (source: malcat). The file is not packed with UPX (source: upx_unpack).

## 2. Classification

| Attribute | Value |
|---|---|
| Verdict | **Malicious** |
| Family | Locky (ransomware) |
| Confidence | 99% |
| Triage Score | 40.0 |
| Triage Confidence | 40 |
| Agreement | `llm_and_v1_agree` |

The classification is based on multiple converging lines of evidence. A direct YARA match for `Locky_Ransomware_2` was triggered (source: malcat). The binary imports a full cryptographic pipeline (`CryptAcquireContextA`, `CryptCreateHash`, `CryptHashData`, `CryptImportKey`, `CryptSetKeyParam`, `CryptEncrypt`, `CryptGenRandom`) from `ADVAPI32.DLL`, which is consistent with ransomware file encryption (source: pe_imports). Decompilation reveals references to `Locky_recover_instructions.txt` and `.bmp` files, confirming the deployment of ransom notes (source: ghidra_query). The sample contains a command to delete Volume Shadow Copies (`vssadmin.exe Delete Shadows /All /Quiet`), a key ransomware behavior to inhibit recovery (source: malcat). External threat intelligence from VirusTotal shows 66 malicious detections with the popular threat name 'locky' (source: external_ti). The registry key `Software\Locky` is present, indicating persistence and family association (source: malcat).

## 3. Background & Family Lineage

Locky is a well-documented ransomware family that first appeared in early 2016. It is typically distributed via malicious Microsoft Office documents containing macros. Once executed, it encrypts a wide range of file types on the victim's system and demands a ransom payment in Bitcoin for the decryption key. Locky has been associated with various cybercrime groups and has undergone numerous variants, often identified by the file extension appended to encrypted files (e.g., `.locky`, `.zepto`, `.odin`, `.thor`, `.aesir`, `.zzzzz`, `.osiris`). The sample analyzed here exhibits the classic `.locky` extension and ransom note naming convention, placing it firmly within this lineage.

## 4. Static Analysis

### 4.1 File Properties
The sample is a 32-bit PE executable with a Rich Header indicating it was compiled with Microsoft Visual C++ 8 (2005) (source: malcat). The import hash (imphash) is `31553623c43827d554ad9e1b7dfa6a5a` (source: rule.yara.json). The file does not have a valid checksum, which is a common anomaly in malware (source: malcat).

### 4.2 Imports
The binary imports 156 functions. The high-signal imports are heavily focused on cryptography and networking, which is a strong indicator of ransomware functionality (source: malcat).

| Category | Key Imports | Signal |
|---|---|---|
| Cryptography | `CryptAcquireContextA`, `CryptCreateHash`, `CryptHashData`, `CryptImportKey`, `CryptSetKeyParam`, `CryptEncrypt`, `CryptGenRandom`, `CryptDestroyKey`, `CryptReleaseContext` | High (score 10) |
| Networking | `InternetOpenA`, `InternetConnectA`, `HttpSendRequestA`, `InternetReadFile`, `InternetWriteFile`, `InternetCloseHandle` | High (score 9) |
| Registry | `RegSetValueExA`, `RegCreateKeyExA`, `RegOpenKeyExA` | High (score 9) |
| Anti-Debug | `IsDebuggerPresent` | High (score 10) |
| Process | `CreateProcessW`, `CreateThread`, `TerminateProcess` | Mid |
| File System | `CreateFileW`, `DeleteFileW`, `GetLogicalDrives` | Mid |
| Network Shares | `WNetAddConnection2W` | High (score 8) |

The presence of `IsDebuggerPresent` indicates an anti-analysis check (source: pe_imports). The `WNetAddConnection2W` import suggests capability to access network shares for lateral encryption (source: malcat).

### 4.3 Strings
Key strings recovered from the binary include:
- **Ransom Note**: `\_Locky_recover_instructions.txt` and `\_Locky_recover_instructions.bmp` (source: ghidra_query).
- **File Extension**: `.locky` (source: ghidra_query).
- **C2 Reporting**: `&encrypted=` and `&act=stats&path=` (source: ghidra_query).
- **C2 Servers**: `91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116` (source: ghidra_query).
- **Shadow Copy Deletion**: `vssadmin.exe Delete Shadows /All /Quiet` (source: malcat).
- **Self-Deletion**: `cmd.exe /C del /Q /F "` (source: ghidra_query).
- **Registry Key**: `Software\Locky` (source: malcat).

### 4.4 YARA Matches
The sample triggered 24 YARA rules. The most significant are:
- `Locky_Ransomware_2`: Direct match for the Locky ransomware family (source: malcat).
- `DeletesVssShadowCopy`: Matches the string for deleting Volume Shadow Copies (source: malcat).
- `AccessNetworkShares`: Indicates capability to spread via network shares (source: malcat).
- `Advapi_Hash_API`: Matches the use of cryptographic hashing APIs (source: malcat).

### 4.5 Capa Analysis
Capa identified 50 capabilities. The top ATT&CK-mapped capabilities are:
- **T1027 - Obfuscated Files or Information**: `encode data using XOR`, `encrypt or decrypt via WinCrypt` (source: capa).
- **T1083 - File and Directory Discovery**: `enumerate files on Windows`, `enumerate files recursively` (source: capa).
- **T1082 - System Information Discovery**: `get disk information`, `check OS version` (source: capa).
- **T1490 - Inhibit System Recovery**: `delete volume shadow copies` (source: capa).
- **T1070.004 - Indicator Removal: File Deletion**: `delete volume shadow copies` (source: capa).
- **T1112 - Modify Registry**: `delete registry value` (source: capa).

### 4.6 Anomalies
MalCat detected several anomalies (source: malcat):
- `CryptoApiUsage` (24 hits): Extensive use of cryptographic functions.
- `SpaghettiFunction` (3 hits): Complex, non-linear code flow, often used for obfuscation.
- `XorInLoop` (15 hits): XOR operations in loops, common for simple encryption or decoding.
- `NoChecksum`: The PE checksum is invalid.
- `RichMultipleLinkers`: The Rich Header indicates multiple linker versions.

## 5. Behavioral Analysis

Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events for this sample. The analysis is based solely on static artifacts. Therefore, no runtime behaviors such as file system changes, network connections, or process creation were observed in a sandbox environment. The capabilities described in this report are inferred from static code analysis and string references.

## 6. Network Analysis & C2

The sample contains six hardcoded C2 IP addresses (source: ghidra_query):

| IP Address | Purpose |
|---|---|
| 91.195.12.187 | C2 Server |
| 195.64.154.114 | C2 Server |
| 149.202.109.205 | C2 Server |
| 51.254.181.122 | C2 Server |
| 78.40.108.39 | C2 Server |
| 188.127.231.116 | C2 Server |

The C2 communication protocol is HTTP-based, as indicated by the import of `InternetOpenA`, `InternetConnectA`, `HttpSendRequestA`, and related functions (source: pe_imports). The strings `&encrypted=` and `&act=stats&path=` suggest the sample reports encryption statistics (e.g., number of files encrypted, system path) to the C2 servers (source: ghidra_query). This is a common feature in ransomware to track campaign effectiveness.

## 7. Capability Assessment

| Capability | Status | Evidence |
|---|---|---|
| File Encryption | **Observed (latent)** | Full crypto pipeline imported; `.locky` extension string present (source: pe_imports, ghidra_query). |
| Ransom Note Deployment | **Observed (latent)** | Strings for `\_Locky_recover_instructions.txt` and `.bmp` present (source: ghidra_query). |
| Volume Shadow Copy Deletion | **Observed (latent)** | `vssadmin.exe Delete Shadows /All /Quiet` string present (source: malcat). |
| C2 Communication | **Observed (latent)** | HTTP client APIs imported; C2 IPs and reporting strings present (source: pe_imports, ghidra_query). |
| Self-Deletion | **Observed (latent)** | `cmd.exe /C del /Q /F "` string present (source: ghidra_query). |
| Anti-Debugging | **Observed (latent)** | `IsDebuggerPresent` imported (source: pe_imports). |
| Network Share Access | **Observed (latent)** | `WNetAddConnection2W` imported; YARA rule `AccessNetworkShares` fired (source: malcat). |
| Persistence | **Not Observed** | No evidence of persistence mechanisms (e.g., Run keys, scheduled tasks) found in the analyzed artifacts. |
| Data Exfiltration | **Not Observed** | No tools or mechanisms for data theft were identified. |

**Note**: All capabilities are marked as "latent" because they are inferred from static analysis. No runtime behavior was observed to confirm execution.

## 8. Attribution

The sample is confidently attributed to the **Locky ransomware family** based on the direct YARA match (`Locky_Ransomware_2`), the presence of the `.locky` file extension, the `Software\Locky` registry key, and the characteristic ransom note naming convention (source: malcat, ghidra_query). The specific threat actor or campaign behind this particular sample cannot be determined from the available evidence. Locky has been operated by various cybercrime groups over the years.

## 9. Indicators of Compromise

### 9.1 File-Based IOCs
| Type | Value |
|---|---|
| SHA256 | `28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb` |
| File Name | `svchost.exe` |
| Imphash | `31553623c43827d554ad9e1b7dfa6a5a` |
| Ransom Note | `\_Locky_recover_instructions.txt` |
| Ransom Note (BMP) | `\_Locky_recover_instructions.bmp` |
| Encrypted File Extension | `.locky` |

### 9.2 Network-Based IOCs
| Type | Value |
|---|---|
| C2 IP | `91.195.12.187` |
| C2 IP | `195.64.154.114` |
| C2 IP | `149.202.109.205` |
| C2 IP | `51.254.181.122` |
| C2 IP | `78.40.108.39` |
| C2 IP | `188.127.231.116` |

### 9.3 Host-Based IOCs
| Type | Value |
|---|---|
| Registry Key | `Software\Locky` |
| Command | `vssadmin.exe Delete Shadows /All /Quiet` |
| Command | `cmd.exe /C del /Q /F "` |

## 10. Detection Rules

### 10.1 YARA Rule
A YARA rule was generated for this sample. The rule file is located at `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/rule.yar` (source: rule.yara.json). The rule contains 24 strings, including the distinctive strings for the ransom note, C2 IPs, and shadow copy deletion command.

### 10.2 Sigma Rule
A Sigma rule was generated for this sample. The rule file is located at `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/rule.yml` (source: rule.yara.json).

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Defense Evasion | Obfuscated Files or Information | T1027 | XOR encoding, WinCrypt encryption (source: capa). |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | `delete volume shadow copies` (source: capa). |
| Defense Evasion | Modify Registry | T1112 | `delete registry value` (source: capa). |
| Defense Evasion | File and Directory Permissions Modification | T1222 | `set file attributes` (source: capa). |
| Discovery | File and Directory Discovery | T1083 | `enumerate files on Windows`, `enumerate files recursively` (source: capa). |
| Discovery | System Information Discovery | T1082 | `get disk information`, `check OS version` (source: capa). |
| Discovery | Query Registry | T1012 | `query or enumerate registry value` (source: capa). |
| Impact | Inhibit System Recovery | T1490 | `delete volume shadow copies` (source: capa). |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP client APIs imported (source: pe_imports). |
| Execution | Shared Modules | T1129 | `LoadLibrary`, `GetProcAddress` imported (source: pe_imports). |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `cmd.exe` usage for self-deletion (source: ghidra_query). |
| Defense Evasion | Debugger Evasion | T1622 | `IsDebuggerPresent` imported (source: pe_imports). |

## 12. Containment, Eradication, Recovery

### 12.1 Containment
- **Isolate** the infected system from the network immediately to prevent lateral movement and C2 communication.
- **Block** the six C2 IP addresses at the network perimeter firewall.
- **Disable** network shares and change credentials for any accounts that may have been used on the infected system.

### 12.2 Eradication
- **Identify** and remove the malicious executable (`svchost.exe`) and any associated files (ransom notes, encrypted files).
- **Remove** the `Software\Locky` registry key if present.
- **Scan** the entire network for other instances of the malware using the provided YARA and Sigma rules.

### 12.3 Recovery
- **Restore** files from clean, offline backups. Do not pay the ransom.
- **Rebuild** the system from a known-good image if backups are unavailable or integrity is questionable.
- **Monitor** the network for any signs of re-infection or C2 communication.

## 13. Recommendations

1. **User Education**: Train users to be cautious of unsolicited emails with attachments, especially Microsoft Office documents containing macros.
2. **Macro Security**: Enforce the principle of least privilege by disabling macros by default and only allowing them from trusted sources.
3. **Backup Strategy**: Maintain regular, offline, and tested backups of critical data. Follow the 3-2-1 backup rule.
4. **Patch Management**: Keep operating systems and software up to date to mitigate vulnerabilities that could be used for initial access.
5. **Endpoint Protection**: Deploy and maintain endpoint detection and response (EDR) solutions capable of detecting ransomware behaviors (e.g., rapid file encryption, shadow copy deletion).
6. **Network Segmentation**: Segment networks to limit the spread of ransomware in case of a breach.
7. **Incident Response Plan**: Develop and regularly test an incident response plan specific to ransomware attacks.

## 14. Appendix A: Evidence Trail

This section documents the audit trail of analysis queries performed during the investigation.

| Timestamp (UTC) | Source | Query/Action |
|---|---|---|
| 2026-08-12 17:51:09 | ghidra_query | `SELECT func_name, size, instruction_count, cyclomatic_complexity, call_out_count, string_ref_count FROM function_metrics ORDER BY size DESC LIMIT 20` |
| 2026-08-12 17:51:09 | ghidra_query | `SELECT name, module FROM imports ORDER BY module, name` |
| 2026-08-12 17:51:24 | ghidra_query | `SELECT sr.func_name, sr.string_value FROM string_refs sr WHERE sr.string_value LIKE '%http%' OR sr.string_value LIKE '%.onion%' OR sr.string_value LIKE '%ransom%' OR sr.string_value LIKE '%bitcoin%' OR sr.string_value LIKE '%.locky%' OR sr.string_value LIKE '%_HELP%' OR sr.string_value LIKE '%.doc%' OR sr.string_value LIKE '%.xls%' ORDER BY sr.func_name LIMIT 50` |
| 2026-08-12 17:51:24 | ghidra_query | `SELECT content, address, length FROM strings WHERE address BETWEEN 75000 AND 78000 ORDER BY address` |
| 2026-08-12 17:51:24 | ghidra_query | `SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%.onion%' OR content LIKE '%bitcoin%' OR content LIKE '%locky%' OR content LIKE '%_HELP%' OR content LIKE '%.encrypted%' OR content LIKE '%payment%' OR content LIKE '%decrypt%' ORDER BY address LIMIT 30` |
| 2026-08-12 17:51:30 | ghidra_query | `SELECT content, address, length FROM strings WHERE content LIKE '%recover%' OR content LIKE '%instruction%' OR content LIKE '%shadow%' OR content LIKE '%vssadmin%' OR content LIKE '%bcdedit%' OR content LIKE '%wevtutil%' OR content LIKE '%wallpaper%' OR content LIKE '%bmp%' ORDER BY address LIMIT 30` |
| 2026-08-12 17:51:39 | ghidra_query | `SELECT sr.func_name, sr.string_value FROM string_refs sr WHERE sr.func_name IN ('FUN_00404044', 'FUN_00401c7a', 'FUN_004034c0', 'FUN_00406ebc', 'FUN_0040684c') ORDER BY sr.func_name, sr.string_value LIMIT 80` |
| 2026-08-12 17:51:39 | ghidra_query | `SELECT content, address FROM strings WHERE content LIKE '%.%' AND length BETWEEN 3 AND 6 AND content NOT LIKE '% %' AND address > 4000000 ORDER BY address LIMIT 40` |
| 2026-08-12 17:51:39 | ghidra_query | `SELECT content, address FROM strings WHERE content LIKE '%cmd%' OR content LIKE '%/c %' OR content LIKE '%taskkill%' OR content LIKE '%wbadmin%' OR content LIKE '%delete%' ORDER BY address LIMIT 20` |
| 2026-08-12 17:51:50 | ghidra_query | `SELECT content, address FROM strings WHERE content LIKE '%.doc%' OR content LIKE '%.xls%' OR content LIKE '%.ppt%' OR content LIKE '%.pdf%' OR content LIKE '%.jpg%' OR content LIKE '%.sql%' OR content LIKE '%.mdb%' ORDER BY address LIMIT 30` |
| 2026-08-12 17:51:53 | ghidra_query | `SELECT sr.func_name, sr.string_value FROM string_refs sr WHERE sr.func_name = 'FUN_00404044' ORDER BY sr.string_value LIMIT 40` |
| 2026-08-12 17:53:15 | ghidra_query | `SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80` |
| 2026-08-12 17:53:17 | ida_query | `SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80` |
| 2026-08-12 17:53:17 | yara_gen_v2 | YARA rule generation completed. |
| 2026-08-12 17:55:25 | publish_report_v2 | Report generation initiated. |
| 2026-08-12 17:58:34 | publish_report_v2_technical | Technical report generation initiated. |
| 2026-08-13 01:27:06 | ghidra_query | `SELECT address, name, size FROM funcs` |
| 2026-08-13 01:27:06 | ghidra_query | `SELECT start_ea, end_ea, name FROM memory_blocks` |
| 2026-08-13 01:27:07 | ghidra_query | `SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'` |
| 2026-08-13 01:27:09 | ghidra_query | `SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR dst_func_name LIKE 'CheckRemoteDebuggerPresent%' OR dst_func_name LIKE 'NtQueryInformationProcess%' OR dst_func_name LIKE 'OutputDebugString%' OR dst_func_name LIKE 'SetUnhandledExceptionFilter%' OR dst_func_name LIKE 'UnhandledExceptionFilter%' OR dst_func_name LIKE 'DebugActiveProcess%' OR dst_func_name LIKE 'NtSetInformationThread%' OR dst_func_name LIKE 'GetThreadContext%' OR dst_func_name LIKE 'SetThreadContext%' OR dst_func_name LIKE 'FindWindowA%' OR dst_func_name LIKE 'FindWindowW%' OR dst_func_name LIKE 'GetWindowThreadProcessId%'` |
| 2026-08-13 01:27:10 | ghidra_query | `SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'SetUnhandledExceptionFilter%' OR dst_func_name LIKE 'UnhandledExceptionFilter%'` |
| 2026-08-13 01:27:12 | ghidra_query | `SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'CreateToolhelp32Snapshot%' OR dst_func_name LIKE 'Process32FirstW%' OR dst_func_name LIKE 'Process32NextW%' OR dst_func_name LIKE 'Process32First%' OR dst_func_name LIKE 'Process32Next%' OR dst_func_name LIKE 'EnumProcesses%' OR dst_func_name LIKE 'NtQuerySystemInformation%' OR dst_func_name LIKE 'EnumProcessModulesEx%' OR dst_func_name LIKE 'GetModuleFileNameExW%' OR dst_func_name LIKE 'GetModuleBaseNameW%'` |
| 2026-08-13 01:27:13 | ghidra_query | `SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetTickCount%' OR dst_func_name LIKE 'GetTickCount64%' OR dst_func_name LIKE 'QueryPerformanceCounter%' OR dst_func_name LIKE 'NtQueryPerformanceCounter%' OR dst_func_name LIKE 'timeGetTime%' OR dst_func_name LIKE 'GetSystemTimeAsFileTime%' OR dst_func_name LIKE 'GetLocalTime%' OR dst_func_name LIKE 'NtGetSystemTime%' OR dst_func_name LIKE 'NtDelayExecution%' OR dst_func_name LIKE 'SleepEx%' OR dst_func_name LIKE 'Sleep%'` |
| 2026-08-13 01:27:13 | ghidra_query | `SELECT address, content FROM strings WHERE length < 300` |
| 2026-08-13 01:27:16 | ghidra_query | `SELECT func_addr, ref_addr, string_addr FROM string_refs` |
| 2026-08-13 01:27:16 | ghidra_query | `SELECT address, name, size FROM funcs` |
| 2026-08-13 01:27:18 | ghidra_query | `SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetProcAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddressForCaller%'` |
| 2026-08-13 01:27:18 | ghidra_query | `SELECT src_func_addr, dst_func_addr FROM call_edges` |
| 2026-08-13 01:27:19 | ghidra_query | `SELECT src_func_addr FROM callgraph_edges WHERE dst_func_name LIKE 'LoadLibraryA%' OR dst_func_name LIKE 'LoadLibraryW%' OR dst_func_name LIKE 'LoadLibraryExA%' OR dst_func_name LIKE 'LoadLibraryExW%' OR dst_func_name LIKE 'LdrLoadDll%' OR dst_func_name LIKE 'GetModuleHandleA%' OR dst_func_name LIKE 'GetModuleHandleW%' OR dst_func_name LIKE 'GetModuleHandleExA%' OR dst_func_name LIKE 'GetModuleHandleExW%'` |
| 2026-08-13 01:27:19 | ghidra_query | `SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'` |
| 2026-08-13 01:27:19 | ghidra_query | `SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'` |
| 2026-08-13 01:27:19 | ghidra_query | `SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25` |
| 2026-08-13 01:27:26 | ghidra_query | `SELECT name, module FROM imports ORDER BY module, name` |
| 2026-08-13 01:27:26 | ghidra_query | `SELECT func_name, func_addr, size, cyclomatic_complexity, call_out_count, string_ref_count FROM function_metrics ORDER BY size DESC LIMIT 30` |
| 2026-08-13 01:27:26 | ghidra_query | `SELECT content, address, length FROM strings WHERE length > 5 ORDER BY length DESC LIMIT 80` |
| 2026-08-13 01:27:41 | ghidra_query | `SELECT content, address FROM strings WHERE content LIKE '%Locky%' OR content LIKE '%.locky%' OR content LIKE '%ransom%' OR content LIKE '%bitcoin%' OR content LIKE '%decrypt%' OR content LIKE '%encrypt%' OR content LIKE '%.onion%' OR content LIKE '%recover%' OR content LIKE '%payment%' OR content LIKE '%ransom%' OR content LIKE '%victim%' OR content LIKE '%restore%' OR content LIKE '%wallet%' OR content LIKE '%btc%' OR content LIKE '%%s_%s%' OR content LIKE '%_HELP%' OR content LIKE '%_Locky%' OR content LIKE '%DECRYPT%' OR content LIKE '%locked%' OR content LIKE '%.doc%'` |
| 2026-08-13 01:27:41 | ghidra_query | `SELECT content, address FROM strings WHERE content LIKE '%http%' OR content LIKE '%.onion%' OR content LIKE '%tor%' OR content LIKE '%server%' OR content LIKE '%POST%' OR content LIKE '%GET%' OR content LIKE '%Mozilla%' OR content LIKE '%Content-Type%' OR content LIKE '%User-Agent%'` |
| 2026-08-13 01:27:54 | ghidra_query | `SELECT content, address FROM strings WHERE content LIKE '%vssadmin%' OR content LIKE '%cmd.exe%' OR content LIKE '%bcdedit%' OR content LIKE '%wbadmin%' OR content LIKE '%shadow%' OR content LIKE '%taskkill%' OR content LIKE '%net stop%' OR content LIKE '%delete%' OR content LIKE '%bootstatuspolicy%' OR content LIKE '%ignoreallfailures%' OR content LIKE '%recoveryenabled%' OR content LIKE '%no%'` |
| 2026-08-13 01:33:42 | publish_report_v2 | Report generation completed. |
| 2026-08-13 01:37:31 | publish_report_v2_technical | Technical report generation completed. |

## 15. Appendix B: Module Inventory

The sample is a monolithic executable. No separate modules or DLLs were identified. The functionality is contained within the single PE file.

## 16. Author + Sign-off

**Report Author**: Automated Malware Analysis System
**Date**: 2026-08-13
**Version**: 2.0

This report was generated based on automated static analysis. All findings are based on the provided evidence and should be verified through manual analysis and dynamic analysis in a controlled environment.