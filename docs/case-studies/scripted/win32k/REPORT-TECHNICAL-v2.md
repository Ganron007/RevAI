> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 02:45:07 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

## 1. Executive Summary

This report details the analysis of a 64-bit Windows DLL (`win32k.dll`) identified as a variant of the Dyreza/Battdil banking trojan. The sample exhibits a comprehensive set of malicious capabilities, including HTTP-based command-and-control (C2) communication, credential theft via cryptographic APIs, process injection for code execution, and persistence mechanisms through scheduled tasks and registry manipulation. The analysis is based on static code analysis, behavioral indicators from multiple engines, and structured evidence from tools such as Ghidra, IDA, MalCat, capa, and YARA. Dynamic analysis with Speakeasy and Frida did not observe runtime events, which may indicate anti-analysis techniques or the need for specific environmental triggers. The verdict is malicious with high confidence (95/100), supported by VirusTotal detections (55/72) and convergent evidence from multiple analysis engines.

## 2. Sample Metadata

| Attribute | Value |
|---|---|
| **SHA256** | `8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde` |
| **File Path** | `/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll` |
| **File Type** | PE (Portable Executable) |
| **Architecture** | x64 (64-bit) |
| **File Size** | 268,800 bytes |
| **Entry Point** | 0x80560 |
| **Entropy** | 7.37 (high, indicating possible packing or encryption) |
| **Family Guess** | Dyreza/Battdil |
| **Verdict** | Malicious (score: 95) |
| **Source** | llm_judge, deep_dive_agentic |

## 3. File Layout & Structural Analysis

The PE file structure is analyzed to understand its sections and potential anomalies. The high entropy (7.37) suggests obfuscation or embedded payloads, particularly in the `.rsrc` section. The file layout table from MalCat shows the sections and their properties.

| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| header | 0 | 1024 | 0 | - |
| .text | 1024 | 99840 | 102400 | RX |
| .rdata | 103424 | 22528 | 24576 | R |
| .data | 128000 | 512 | 12288 | RW |
| .pdata | 140288 | 9216 | 12288 | R |
| .rsrc | 152576 | 135168 | 135168 | R |
| .reloc | 287744 | 512 | 4096 | R |

**Interpretation**: The `.rsrc` section is notably large (135,168 bytes) and has high entropy, which aligns with the MalCat anomaly `BigResourceHighEntropy×4` (source: malcat, Anomalies, BigResourceHighEntropy×4). This suggests embedded or encrypted payloads. The `.text` section is executable and contains the main code. The entry point at 0x80560 is within the `.text` section, indicating standard DLL initialization. The file is not packed with UPX (source: UPX Unpack, upx_ok: False), but the high entropy may indicate custom packing or encryption.

## 4. Static Code Analysis

Static analysis reveals extensive malicious functionality through imports, strings, and code patterns. The sample imports numerous APIs for network communication, cryptographic operations, process manipulation, and registry access. Key findings are summarized below.

### 4.1 Import Analysis

The sample imports 192 functions from various DLLs, including `WININET.DLL`, `ADVAPI32.DLL`, `KERNEL32.DLL`, `BCRYPT.DLL`, and `WS2_32.DLL`. These imports indicate capabilities for HTTP communication, cryptographic operations, process injection, and privilege escalation.

**High-Signal Imports** (source: malcat, Top high-signal imports):
- `kernel32.CreateRemoteThread`: Process injection API.
- `advapi32.CryptAcquireContextW`, `advapi32.CryptCreateHash`, `advapi32.CryptHashData`: Cryptographic APIs for credential theft or data encryption.
- `wininet.InternetConnectA`, `wininet.HttpSendRequestA`, `wininet.InternetReadFile`: HTTP client APIs for C2 communication.

**PE Import Signals** (source: pe_imports, pe_imports):
- `create_remote_thread (CreateRemoteThread) [T1055]`: Process injection.
- `http_client (InternetOpen) [T1071.001]`: HTTP client for C2.
- `set_registry_value (RegSetValue) [T1112]`: Registry manipulation.
- `create_process (CreateProcess) [T1106]`: Process creation.
- `shell_execute (ShellExecute) [T1106]`: Shell execution.
- `get_proc_address (GetProcAddress) [T1129]`: Dynamic API resolution.
- `allocate_memory (VirtualAlloc) [T1055]`: Memory allocation for injection.

### 4.2 String Analysis

Strings extracted from the sample reveal C2 URLs, registry paths, and suspicious commands. Key strings include:

- `http://icanhazip.com`: External IP check for C2 communication or environment fingerprinting (source: ghidra, Suspicious strings (Ghidra), `http://icanhazip.com`).
- `CryptGetHashParam, CryptAcquireContextW, CryptCreateHash, CryptHashData`: Cryptographic API strings (source: ghidra, Suspicious strings (Ghidra), `CryptGetHashParam, CryptAcquireContextW, CryptCreateHash, CryptHashData`).
- `HttpSendRequestExW, HttpQueryInfoW, HttpOpenRequestA, HttpSendRequestA`: HTTP client API strings (source: ghidra, Suspicious strings (Ghidra), `HttpSendRequestExW, HttpQueryInfoW, HttpOpenRequestA, HttpSendRequestA`).
- `Software\Microso..ccounts\UserList, Software\Microso..Version\Winlogon`: Registry paths for persistence or credential theft (source: malcat, Strings/registry, `Software\Microso..ccounts\UserList, Software\Microso..Version\Winlogon`).
- `Tcmd.exe`: Suspicious executable name (source: malcat, Strings/suspicious, `Tcmd.exe`).
- `C:\windows\system32\shutdown.exe, \\.\pipe\, \\.\PhysicalDrive0`: System paths for potential destructive actions (source: malcat, Strings/paths, `C:\windows\system32\shutdown.exe, \\.\pipe\, \\.\PhysicalDrive0`).

### 4.3 Code Patterns and Anomalies

MalCat identifies several code anomalies that suggest obfuscation or malicious behavior:

- `XorInLoop×16`: XOR instructions in loops, indicating encryption or obfuscation (source: malcat, Anomalies, XorInLoop×16).
- `ManyHighValueImmediates×1`: High-value immediate operands, possibly for obfuscation (source: malcat, Anomalies, ManyHighValueImmediates×1).
- `SequentialFunction×3`: Functions with little intra jumps, often crypto functions (source: malcat, Anomalies, SequentialFunction×3).

### 4.4 Disassembly Excerpts

The entry point and key functions are disassembled to understand execution flow. The entry point (`0x1800146b0`) is a standard DLL entry that calls initialization functions based on the `fdwReason` parameter.

```asm
┌ 42: entry0 (int64_t arg1, int64_t arg2);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           0x1800146b0      4883ec28       sub rsp, 0x28
│           0x1800146b4      85d2           test edx, edx              ; arg2
│       ┌─< 0x1800146b6      7413           je 0x1800146cb
│       │   0x1800146b8      ffca           dec edx                    ; arg2
│      ┌──< 0x1800146ba      7514           jne 0x1800146d0
│      ││   0x1800146bc      e84f390000     call fcn.180018010
│      ││   0x1800146c1      b801000000     mov eax, 1
│      ││   0x1800146c6      4883c428       add rsp, 0x28
│      ││   0x1800146ca      c3             ret
│      │└─> 0x1800146cb      e8c0390000     call fcn.180018090
│      └──> 0x1800146d0      b801000000     mov eax, 1
│           0x1800146d5      4883c428       add rsp, 0x28
└           0x1800146d9      c3             ret
```

**Interpretation**: The entry point checks the `fdwReason` parameter (in `edx`). If it is 0 (DLL_PROCESS_ATTACH), it calls `fcn.180018090`; if it is 1 (DLL_THREAD_ATTACH), it calls `fcn.180018010`. This is typical for DLL initialization. The functions called likely contain the malware's main logic.

The function `sub_180009be0` (at EA 36832) demonstrates HTTP C2 communication. It uses `HttpOpenRequestA`, `HttpSendRequestA`, and `InternetReadFile` to send and receive data. The decompilation shows error handling and data processing loops, indicating a robust C2 protocol.

```c
uint64_t sub_180009be0(int64_t param_1)
{
    // ... (code omitted for brevity)
    iVar5 = (*wininet.HttpOpenRequestA)(*(param_1 + 0x10), 0x18001ad04, *(param_1 + 0xb0), 0, 0, 0, uVar2, 0);
    // ... error handling ...
    iVar1 = (*wininet.HttpSendRequestA)(iVar5, 0, 0, 0, uVar4 & 0xffffffff00000000);
    // ... read response ...
    iVar1 = (*wininet.InternetReadFile)(iVar5, iVar6, auStackX_8[0], aiStackX_10);
    // ... process data ...
}
```

**Interpretation**: This function implements an HTTP client that opens a request, sends it, and reads the response. The use of `HttpOpenRequestA` with a URL (at 0x18001ad04) suggests C2 communication. The loop reading data indicates a persistent connection or data exfiltration capability.

## 5. Behavioral & Dynamic Analysis

Dynamic analysis with Speakeasy and Frida did not observe any runtime events. This may be due to anti-analysis techniques, environmental checks, or the need for specific triggers (e.g., network connectivity, user interaction). The lack of observed events does not negate the static evidence of malicious capabilities.

- **Speakeasy**: Ran successfully but recorded zero API calls or key events (source: Speakeasy, api_calls: 0, key_events: 0).
- **Frida Probe**: Available and identified hook candidates, but no runtime events were recorded (source: Frida Probe, frida_available: True).

**Interpretation**: The absence of dynamic behavior suggests the sample may employ anti-analysis techniques, such as checking for virtual machines, debuggers, or specific system configurations. Alternatively, the sample may require activation via a specific event (e.g., network request, registry change). Static analysis provides sufficient evidence of malicious intent.

## 6. Network Indicators & C2

The sample uses HTTP for C2 communication, with indicators including URLs, user-agent strings, and custom protocols.

- **C2 URL**: `http://icanhazip.com` for external IP check (source: ghidra, Suspicious strings (Ghidra), `http://icanhazip.com`).
- **Custom Protocols**: Strings `httprdc` and `httprex` suggest a custom HTTP-based C2 protocol (source: deep_dive_agentic, key_evidence, `Custom C2 protocol strings 'httprdc' and 'httprex'`).
- **User-Agent**: Masquerades as Chrome: `Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36` (source: deep_dive_agentic, key_evidence, `User-Agent masquerade as Chrome`).
- **OS Fingerprinting**: Beacon URL pattern `/%s/%s/0/%s/%d/%s/%s/` with version strings for OS fingerprinting (source: deep_dive_agentic, key_evidence, `OS fingerprinting beacon URL`).

**Interpretation**: The HTTP-based C2 allows the malware to blend with normal web traffic. The custom protocols (`httprdc`/`httprex`) indicate a structured command-response system. The user-agent masquerading as Chrome helps evade detection. OS fingerprinting enables tailored attacks or environment checks.

## 7. Capabilities Assessment

The sample exhibits the following capabilities, supported by static evidence:

| Capability | Evidence | Confidence |
|---|---|---|
| **C2 Communication** | HTTP APIs, custom protocols, external IP check | High |
| **Credential Theft** | Cryptographic APIs (BCrypt, CryptoAPI), browser targeting | High |
| **Process Injection** | `CreateRemoteThread`, `VirtualAlloc`, `OpenProcess` | High |
| **Persistence** | Scheduled tasks, registry manipulation | High |
| **Privilege Escalation** | `AdjustTokenPrivileges`, `DuplicateTokenEx`, `CreateProcessAsUserW` | High |
| **System Reconnaissance** | OS fingerprinting, process enumeration, file discovery | High |
| **Defense Evasion** | Masquerading as `win32k.dll`, encryption layers, high entropy | Medium |

**Interpretation**: The capabilities indicate a fully-featured backdoor/RAT designed for credential theft, remote control, and persistence. The use of multiple encryption layers (AES, XOR, Base64) and masquerading as a legitimate Windows component (`win32k.dll`) suggests sophisticated evasion techniques.

## 8. Indicators of Compromise

| Type | Value | Source |
|---|---|---|
| **SHA256** | `8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde` | Sample |
| **File Name** | `win32k.dll` | Sample |
| **C2 URL** | `http://icanhazip.com` | ghidra |
| **Registry Paths** | `Software\Microso..ccounts\UserList`, `Software\Microso..Version\Winlogon` | malcat |
| **Suspicious Executable** | `Tcmd.exe` | malcat |
| **User-Agent** | `Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36` | deep_dive_agentic |
| **Custom Protocols** | `httprdc`, `httprex` | deep_dive_agentic |
| **Scheduled Task Command** | `/c echo N|schtasks /create /tn "%s" /tr "%s" /sc minute /mo 1 /ru "System"` | deep_dive_agentic |

## 9. Detection Engineering

Detection rules can be based on the identified indicators and behaviors. YARA rules are generated from the sample's strings and patterns.

**Generated YARA Meta** (source: rule.yara.json):
- Family: `trojan.dyreza/battdil`
- Import Hash: `8d7e3e41cd993d5a41f4e96d6076c4f7`
- Strings: 24 strings, including `=&&jL66Zl??A~`, `daYdnceM`, etc.

**YARA Matches** (source: YARA Matches, pipeline):
- `network_http`, `network_tcp_socket`: Network communication rules.
- `escalate_priv`, `win_token`, `win_registry`: Privilege escalation and registry rules.
- `Advapi_Hash_API`: Cryptographic API usage.
- `SHA2_BLAKE2_IVs`: Embedded cryptographic constants.

**Interpretation**: The YARA rules can be used for detection in network and endpoint security tools. The import hash is useful for identifying similar samples. The custom strings (`daYdnceM`) may be unique to this variant.

## 10. MITRE ATT&CK Mapping

The sample's capabilities map to the following MITRE ATT&CK techniques:

| Technique | ID | Evidence |
|---|---|---|
| **Obfuscated Files or Information** | T1027 | Base64, XOR, AES encoding (source: capa, ATT&CK, T1027) |
| **File and Directory Discovery** | T1083 | File system reconnaissance (source: capa, ATT&CK, T1083) |
| **Query Registry** | T1012 | Registry enumeration (source: capa, ATT&CK, T1012) |
| **System Information Discovery** | T1082 | System fingerprinting (source: capa, ATT&CK, T1082) |
| **Process Discovery** | T1057 | Process enumeration (source: capa, ATT&CK, T1057) |
| **Windows Service** | T1543.003 | Service manipulation (source: capa, ATT&CK, T1543.003) |
| **Process Injection** | T1055 | `CreateRemoteThread` (source: pe_imports, pe_imports, T1055) |
| **Application Layer Protocol: Web Protocols** | T1071.001 | HTTP client (source: pe_imports, pe_imports, T1071.001) |
| **Modify Registry** | T1112 | Registry manipulation (source: pe_imports, pe_imports, T1112) |
| **Create or Modify System Process** | T1106 | Process creation (source: pe_imports, pe_imports, T1106) |

## 11. What We Don't Know

Several aspects remain unknown due to tool limitations or sample behavior:

- **Dynamic Behavior**: Speakeasy and Frida did not observe runtime events, so the exact activation mechanism and real-time C2 protocol are unknown. This may be due to anti-analysis techniques or environmental checks.
- **C2 Server Addresses**: The sample contains `http://icanhazip.com` for IP checking, but the actual C2 server addresses are not identified in the strings. They may be hardcoded, encrypted, or fetched dynamically.
- **Payload Delivery**: The high-entropy `.rsrc` section suggests embedded payloads, but their exact content and delivery mechanism are unknown without dynamic execution.
- **Persistence Mechanisms**: While scheduled tasks and registry paths are identified, the exact persistence triggers and conditions are not fully understood.
- **Credential Theft Targets**: The sample targets browsers (Chrome, Firefox, IE, Edge), but the specific data stolen (e.g., passwords, cookies) and exfiltration method are not observed.
- **Anti-Analysis Techniques**: The lack of dynamic behavior suggests anti-analysis, but specific techniques (e.g., VM detection, debugger checks) are not identified in static analysis.

## 12. Appendix A: Tool Evidence Trail

This appendix summarizes the evidence from each analysis engine, with citations to the structured evidence.

| Engine | Key Findings | Source Citation |
|---|---|---|
| **Ghidra** | HTTP and crypto API strings, function metrics, string references | ghidra, Suspicious strings (Ghidra), function_metrics |
| **IDA** | HTTP and Winsock imports | ida, Imports (IDA) |
| **MalCat** | Anomalies (XOR, high entropy), high-signal imports, strings | malcat, Anomalies, Top high-signal imports, Strings |
| **capa** | 74 behavioral rules mapping to MITRE ATT&CK | capa, ATT&CK |
| **YARA** | Network, privilege escalation, and crypto rules | yara, YARA matches |
| **pe_imports** | Process injection, HTTP client, registry manipulation | pe_imports, pe_imports |
| **Speakeasy** | No runtime events observed | Speakeasy, api_calls: 0 |
| **Frida Probe** | Hook candidates identified, no events | Frida Probe, frida_available: True |
| **UPX** | Not packed with UPX | UPX Unpack, upx_ok: False |
| **FLOSS** | 907 strings, including decoded and static strings | FLOSS Strings, total strings: 907 |

## 13. Appendix B: Analysis Environment

The analysis was performed in a controlled environment with the following tools and configurations:

- **Static Analysis**: Ghidra, IDA, MalCat, capa, YARA, pe_imports, FLOSS, radare2.
- **Dynamic Analysis**: Speakeasy, Frida Probe (version 17.16.4).
- **Unpacking**: UPX (attempted, but sample not packed).
- **String Extraction**: FLOSS (907 strings extracted).
- **Environment**: Linux-based analysis platform with access to the sample file.

**Note**: Dynamic analysis did not observe runtime events, possibly due to anti-analysis techniques or environmental triggers. Static analysis provides sufficient evidence for the verdict.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde  
**sample_path:** /opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 95
- **family_guess**: Dyreza/Battdil
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple engines (Ghidra, IDA, MalCat, capa, YARA, pe_imports) converge on a DLL with extensive C2, credential theft, and persistence capabilities. The sample uses HTTP for C2 (wininet APIs, 'http://icanhazip.com'), cryptographic APIs for credential theft (BCrypt, CryptoAPI), process injection (CreateRemoteThread), and registry manipulation for persistence. High entropy in .rsrc section suggests embedded payloads. VirusTotal confirms 55/72 detections as Dyreza/Battdil trojan.
- **summary**: This 64-bit DLL (win32k.dll) is identified as Dyreza/Battdil trojan with high confidence (95/100). The sample exhibits comprehensive malicious capabilities: HTTP-based C2 communication using wininet APIs with external IP check (http://icanhazip.com), credential theft via cryptographic APIs (BCrypt, CryptoAPI), process injection via CreateRemoteThread, registry manipulation for persistence, and system reconnaissance. Multiple engines confirm behavioral intent: Ghidra/IDA show HTTP and crypto API imports, MalCat identifies crypto/downloader anomalies and high-entropy resources, capa maps to MITRE ATT&CK techniques for defense evasion, discovery, and persistence, YARA matches network and privilege escalation rules, and pe_imports confirms high-signal APIs. VirusTotal reports 55/72 detections as Dyreza/Battdil. The sample's obfuscation (XOR loops, high entropy) is secondary to its clear behavioral intent for credential theft, C2 communication, and persistence.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| ghidra | Suspicious strings (Ghidra) | `http://icanhazip.com` | External IP check URL indicates C2 communication or environment fingerprinting. |
| ghidra | Suspicious strings (Ghidra) | `CryptGetHashParam, CryptAcquireContextW, CryptCreateHash, CryptHashData` | Cryptographic API strings indicate credential theft or data encryption capabilities. |
| ghidra | Suspicious strings (Ghidra) | `HttpSendRequestExW, HttpQueryInfoW, HttpOpenRequestA, HttpSendRequestA` | HTTP client API strings indicate C2 communication capabilities. |
| ida | Imports (IDA) | `WININET | InternetConnectA, WININET | HttpSendRequestExW, WININET | InternetRead` | HTTP client imports confirm C2 communication functionality. |
| ida | Imports (IDA) | `WS2_32 | WSAConnect, WS2_32 | WSASend, WS2_32 | WSARecv` | Winsock imports indicate additional network communication capabilities. |
| malcat | Anomalies | `CryptoApiUsage×3 (imports)` | Cryptographic API usage indicates credential theft or data encryption. |
| malcat | Anomalies | `DownloaderApiUsage×6 (imports)` | Downloader API usage indicates payload retrieval capabilities. |
| malcat | Anomalies | `BigResourceHighEntropy×4 (resources)` | High-entropy resources suggest embedded/encrypted payloads. |
| malcat | Top high-signal imports | `kernel32.CreateRemoteThread` | Process injection API indicates code injection capabilities. |
| malcat | Top high-signal imports | `advapi32.CryptAcquireContextW, advapi32.CryptCreateHash, advapi32.CryptHashData` | Cryptographic APIs for credential theft or data encryption. |
| malcat | Top high-signal imports | `wininet.InternetConnectA, wininet.HttpSendRequestA, wininet.InternetReadFile` | HTTP client APIs for C2 communication. |
| malcat | Strings/registry | `Software\Microso..ccounts\UserList, Software\Microso..Version\Winlogon` | Registry paths indicate persistence or credential theft targeting Windows authentication. |
| malcat | Strings/suspicious | `Tcmd.exe` | Suspicious executable name suggests command execution capabilities. |
| malcat | Strings/paths | `C:\windows\system32\shutdown.exe, \\.\pipe\, \\.\PhysicalDrive0` | System paths indicate potential destructive actions or system manipulation. |
| capa | ATT&CK | `T1027 - Obfuscated Files or Information` | Multiple encoding techniques (Base64, XOR, AES) indicate defense evasion. |
| capa | ATT&CK | `T1083 - File and Directory Discovery` | File system reconnaissance capabilities. |
| capa | ATT&CK | `T1012 - Query Registry` | Registry enumeration for persistence or credential theft. |
| capa | ATT&CK | `T1082 - System Information Discovery` | System fingerprinting for C2 communication. |
| capa | ATT&CK | `T1057 - Process Discovery` | Process enumeration for injection or termination. |
| capa | ATT&CK | `T1543.003 - Windows Service` | Service manipulation for persistence. |
| malcat | malcat_evidence | `PublicIP` | Public IP detection rule indicates C2 communication or environment fingerprinting. |
| yara | YARA matches | `network_http, network_tcp_socket` | Network communication rules indicate C2 capabilities. |
| yara | YARA matches | `escalate_priv, win_token, win_registry` | Privilege escalation, token manipulation, and registry rules indicate malicious behavior. |
| pe_imports | pe_imports | `create_remote_thread (CreateRemoteThread) [T1055]` | Process injection API indicates code injection capabilities. |
| pe_imports | pe_imports | `http_client (InternetOpen) [T1071.001]` | HTTP client API indicates C2 communication. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 98
- **summary**: This 64-bit DLL (named 'win32k.dll' to masquerade as the legitimate Windows kernel component) is a fully-featured backdoor/RAT with 855 exports, HTTP-based C2, persistence via scheduled tasks, privilege escalation, process injection, and browser credential theft capabilities. It fingerprints the OS version for beaconing, checks its public IP via icanhazip.com, uses a custom HTTP protocol ('httprdc'/'httprex'), and employs multiple encryption layers (AES, XOR, Base64, SHA-2/BLAKE2). Evasion techniques are evident through masquerading as 'win32k.dll' and using encryption layers to hinder analysis. Exfiltration capabilities are not explicitly observed, though data theft is implied via credential theft and HTTP C2. Defense impairment techniques are not observed.

### deep key_evidence
- `"855 exports in a single DLL is abnormal and consistent with a modular malware framework (Ghidra exports table: 855 rows)"`
- `"Persistence via scheduled tasks every 1 minute running as System: '/c echo N|schtasks /create /tn \"%s\" /tr \"%s\" /sc minute /mo 1 /ru \"System\"' (Ghidra string_refs to FUN_18000bf10)"`
- `"Privilege escalation APIs imported: AdjustTokenPrivileges, DuplicateTokenEx, CreateProcessAsUserW, LookupPrivilegeValueW, OpenProcessToken, GetTokenInformation (Ghidra imports from ADVAPI32.DLL)"`
- `"Process injection: CreateRemoteThread + VirtualAlloc + OpenProcess from KERNEL32.DLL (pe_import_signals: T1055 injection)"`
- `"HTTP C2 channel: InternetOpenA, InternetConnectA, HttpOpenRequestA, HttpSendRequestA, HttpSendRequestExW, InternetReadFile (Ghidra imports from WININET.DLL)"`
- `"External IP check via http://icanhazip.com referenced in FUN_180013cb0 (Ghidra string_refs)"`
- `"Custom C2 protocol strings 'httprdc' and 'httprex' with command-response pattern including 'success' and 'no\\r\\n\\r\\n\\r\\n' (Ghidra string_refs to FUN_18000deb0, FUN_18000e4d0, FUN_18000e6e0)"`
- `"OS fingerprinting beacon URL: '/%s/%s/0/%s/%d/%s/%s/' with version strings Win_XP through Win_10_TH1 and _64bit detection (Ghidra string_refs to FUN_180005120)"`
- `"Browser credential theft targeting: chrome.exe, firefox.exe, iexplore.exe, microsoftedge (Ghidra string_refs to FUN_180018b90)"`
- `"CAPA: 74 behavioral rules including Base64 encoding (T1027), XOR encoding (T1027), manually built AES constants (T1027), socket operations, registry manipulation (T1112), process creation (T1106)"`
- `"YARA SHA2/BLAKE2 IVs match at offsets 40612-40665 indicating embedded cryptographic constants (checklist_yara_scan)"`
- `"YARA Advapi_Hash_API matches: CryptAcquireContext, CryptCreateHash, CryptHashData at offsets 120654-120914 (checklist_yara_scan)"`
- `"BCrypt cryptographic API chain: BCryptOpenAlgorithmProvider, BCryptCreateHash, BCryptHashData, BCryptFinishHash, BCryptVerifySignature (Ghidra imports from BCRYPT.DLL)"`
- `"Extremely high cyclomatic complexity functions: CC=97 (FUN_18000b5e0, 144 blocks), CC=91 (FUN_18000d940, 118 blocks), CC=75 (FUN_180015390, 109 blocks) indicating obfuscated or complex C2 logic (Ghidra function_metrics)"`
- `"Service manipulation: ControlService imported from ADVAPI32.DLL (Ghidra imports)"`
- `"User-Agent masquerade as Chrome: 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36' (Ghidra string_refs to FUN_1800095b0)"`
- `"YARA Dropper_Strings match and Misc_Suspicious_Strings match at offsets 108846 and 104200 (checklist_yara_scan)"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde
size: 268800
type: PE
architecture: X64
entrypoint_ea: 80560
entropy: 7.37
file_name: win32k.dll
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| header | 0 | 1024 | 0 | - |
| .text | 1024 | 99840 | 102400 | RX |
| .rdata | 103424 | 22528 | 24576 | R |
| .data | 128000 | 512 | 12288 | RW |
| .pdata | 140288 | 9216 | 12288 | R |
| .rsrc | 152576 | 135168 | 135168 | R |
| .reloc | 287744 | 512 | 4096 | R |

### Malcat YARA / Signatures (12)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2010_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| PublicIP | network | SUSPICIOUS | 90 | program tries to get its public IP address using well-known services |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| CustomUserAgent | network | UNCOMMON | 30 | embeds a user agent string |
| PostHttpForm | network | UNCOMMON | 70 | post data using http form |
| ProcessInjectionTargets | evasion | UNCOMMON | 20 | contains a list of process names often used as injection target in Windows |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | tries to assess the O.S environment |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |
| CreateScheduledTask | persistence | UNCOMMON | 60 | can create a scheduled task |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (10)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| DllNoExportTable | 4 | exports | 1 | no valid ExportDirectory found and PE is a DLL |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| PossiblePackerApiDynamicImport | 4 | imports | 1 | A packer-related api (VirtualProtect, ResumeThread, etc.) is present as string in the binary, but is |
| ManyHighValueImmediates | 3 | code | 1 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| XorInLoop | 3 | code | 16 | XOR instruction in a loop |
| BigResourceHighEntropy | 2 | resources | 4 | File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture |
| CryptoApiUsage | 2 | imports | 3 | Crypto-related apis are used |
| DownloaderApiUsage | 2 | imports | 6 | Downloader-related apis are used |
| RcdataNoDelphi | 2 | resources | 7 | File contains a rcdata resource and is not a delphi application |
| SequentialFunction | 1 | code | 3 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |

### Anomaly Locations (high-signal)
- **BigResourceHighEntropy**
  - `153164`: 
  - `207780`: 
  - `274392`: 
  - `280172`: 
- **CryptoApiUsage**
  - `27506`: 
  - `27483`: 
  - `27341`: 
- **ManyHighValueImmediates**
  - `40608`: 
- **SequentialFunction**
  - `39648`: 
  - `63280`: 
  - `65472`: 
- **XorInLoop**
  - `32256`: 
  - `39808`: 
  - `40112`: 
  - `62608`: 
  - `62672`: 

### High-Signal Strings (21 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 110792 | `http://icanhazip.com` |
| 106960 | `kernel32.dll` |
| 105944 | `\\.\pipe\` |
| 106776 | `\\.\PhysicalDrive0` |
| 106832 | `\\.\D:` |
| 106816 | `\\.\C:` |
| 111960 | `GetProcAddress` |
| 109256 | `httprex` |
| 125594 | `KERNEL32.dll` |
| 109216 | `httprdc` |
| 124128 | `bcrypt.dll` |
| 106758 | `Tcmd.exe` |
| 122708 | `HttpAddRequestHeadersA` |
| 124016 | `BCryptCloseAlgorithmProvider` |
| 124110 | `BCryptGetProperty` |
| 123904 | `BCryptOpenAlgorithmProvider` |
| 123992 | `BCryptVerifySignature` |
| 123364 | `CryptCreateHash` |
| 123278 | `CryptReleaseContext` |
| 124070 | `BCryptDestroyKey` |
| 124090 | `BCryptCreateHash` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 108432 | `Software\Microso..ccounts\UserList` |
| 108144 | `Software\Microso..Version\Winlogon` |
| 108288 | `Software\Microso..\SpecialAccounts` |
| 106640 | `Mozilla/5.0 (Win...0 Safari/537.36` |
| 112160 | `Internet Explorer\iexplore.exe` |
| 107088 | `/c "echo N|schta..sc minute /mo 1"` |
| 107216 | `/c "echo N|schta.. 1 /ru "System""` |
| 108600 | `explorer.exe` |
| 107872 | `\explorer.exe` |
| 112024 | `iexplore.exe` |
| 110792 | `http://icanhazip.com` |
| 106520 | `Content-Type: mu..-data; boundary=` |
| 105496 | `SeDebugPrivilege` |
| 111248 | `Software\Microso..ersion\Uninstall` |
| 108816 | `SYSTEM\CurrentCo..\Terminal Server` |
| 108688 | `SYSTEM\CurrentCo..lSet\Control\Lsa` |
| 111392 | `SYSTEM\CurrentCo..trolSet\services` |
| 105664 | `C:\windows\system32\shutdown.exe` |
| 107408 | `D:P(A;;GA;;;SY)(..;;NW;;;S-1-16-0)` |
| 107584 | `D:P(A;;GA;;;SY)(..)S:(ML;;NW;;;LW)` |
| 107728 | `D:P(A;CIOI;FA;;;..(A;CIOI;FA;;;WD)` |
| 112000 | `firefox.exe` |
| 109696 | `stun1.voiceeclipse.net` |
| 109664 | `microsoft.com` |
| 109640 | `google.com` |
| 107016 | `advapi32.dll` |
| 106992 | `wininet.dll` |
| 106960 | `kernel32.dll` |
| 105760 | `CPU: %s
Process.. %d
Memory: %d ` |
| 111976 | `chrome.exe` |
| 105616 | `ntdll.dll` |
| 108920 | `fSingleSessionPerUser` |
| 105640 | `/r /f /t 5` |
| 106592 | `
Accept: text/h..: Keep-Alive

` |
| 106424 | `
--%s
Content-..ata; name="%s"
` |
| 125000 | `CreateToolhelp32Snapshot` |
| 105944 | `\\.\pipe\` |
| 109512 | `ECCPUBLICBLOB` |
| 106896 | `\System32\drivers\` |
| 108768 | `fDenyTSConnections` |
| 109576 | `HashDigestLength` |
| 105536 | `SeShutdownPrivilege` |
| 108632 | `LimitBlankPasswordUse` |
| 108024 | `Administrators` |
| 108056 | `localgroup %s %s /add` |
| 122608 | `InternetReadFile` |
| 106776 | `\\.\PhysicalDrive0` |
| 106832 | `\\.\D:` |
| 106816 | `\\.\C:` |
| 111864 | `wscsvc` |
| 124674 | `GetComputerNameW` |
| 111464 | `
==Services==
` |
| 125350 | `GetComputerNameA` |
| 110880 | `Address restricted NAT` |
| 106872 | `C:\Users\` |
| 110968 | `4fggn9gak` |
| 123418 | `AdjustTokenPrivileges` |
| 111896 | `WinDefend` |
| 108104 | `SpecialAccounts` |
| 108976 | `7mcic6hxh` |
| 112056 | `microsoftedge` |
| 109544 | `ObjectLength` |
| 106496 | `

` |
| 125792 | `ShellExecuteW` |
| 111920 | `C:\Program Files\` |
| 109008 | `%02X%02X%02X%02X..%02X%02X%02X%02X` |
| 112088 | `RtlCreateUserThread` |
| 111192 | `==Users==
` |
| 105584 | `RtlTimeToSecondsSince1970` |
| 107992 | `user %s %s /add` |
| 111160 | `==General==
` |
| 111352 | `==Programs==
` |
| 111832 | `send system info failed` |
| 109160 | `success` |
| 124972 | `GetSystemInfo` |
| 125294 | `Process32NextW` |
| 110992 | `3dfrm0tfi` |
| 108256 | `UserList` |
| 106936 | `\System32\` |
| 105928 | `Global\` |

### Constants / Known Patterns (4)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| registry | `registry::HKEY_USERS` |
| hash | `hash::SHA256` |

### Imports (192)
| EA | Name | Type | Refs |
|---|---|---|---|
| 103424 | advapi32.OpenProcessToken | IMPORT | 10 |
| 103432 | advapi32.RegEnumKeyExW | IMPORT | 2 |
| 103440 | advapi32.RegOpenKeyW | IMPORT | 1 |
| 103448 | advapi32.QueryServiceConfigW | IMPORT | 2 |
| 103456 | advapi32.ControlService | IMPORT | 1 |
| 103464 | advapi32.FreeSid | IMPORT | 1 |
| 103472 | advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW | IMPORT | 1 |
| 103480 | advapi32.EnumServicesStatusW | IMPORT | 1 |
| 103488 | advapi32.AllocateAndInitializeSid | IMPORT | 1 |
| 103496 | advapi32.DuplicateTokenEx | IMPORT | 1 |
| 103504 | advapi32.CreateProcessAsUserW | IMPORT | 1 |
| 103512 | advapi32.OpenServiceW | IMPORT | 2 |
| 103520 | advapi32.LogonUserW | IMPORT | 1 |
| 103528 | advapi32.OpenSCManagerW | IMPORT | 2 |
| 103536 | advapi32.DeleteService | IMPORT | 1 |
| 103544 | advapi32.CloseServiceHandle | IMPORT | 4 |
| 103552 | advapi32.CryptHashData | IMPORT | 1 |
| 103560 | advapi32.RegSetValueExW | IMPORT | 1 |
| 103568 | advapi32.RegCloseKey | IMPORT | 5 |
| 103576 | advapi32.AdjustTokenPrivileges | IMPORT | 2 |
| 103584 | advapi32.CryptDestroyHash | IMPORT | 1 |
| 103592 | advapi32.RegOpenKeyExW | IMPORT | 3 |
| 103600 | advapi32.CryptCreateHash | IMPORT | 1 |
| 103608 | advapi32.LookupAccountSidW | IMPORT | 3 |
| 103616 | advapi32.LookupPrivilegeValueW | IMPORT | 2 |
| 103624 | advapi32.RegQueryValueExW | IMPORT | 1 |
| 103632 | advapi32.CryptReleaseContext | IMPORT | 1 |
| 103640 | advapi32.RegCreateKeyExW | IMPORT | 1 |
| 103648 | advapi32.GetTokenInformation | IMPORT | 3 |
| 103656 | advapi32.CryptAcquireContextW | IMPORT | 1 |
| 103664 | advapi32.CryptGetHashParam | IMPORT | 2 |
| 103680 | iphlpapi.GetAdaptersAddresses | IMPORT | 3 |
| 103696 | kernel32.GetSystemInfo | IMPORT | 2 |
| 103704 | kernel32.GlobalMemoryStatusEx | IMPORT | 1 |
| 103712 | kernel32.LockResource | IMPORT | 1 |
| 103720 | kernel32.GetLocalTime | IMPORT | 1 |
| 103728 | kernel32.VirtualAlloc | IMPORT | 3 |
| 103736 | kernel32.GetProcAddress | IMPORT | 5 |
| 103744 | kernel32.OpenMutexW | IMPORT | 1 |
| 103752 | kernel32.lstrlenW | IMPORT | 28 |
| 103760 | kernel32.CreateFileW | IMPORT | 6 |
| 103768 | kernel32.ReadFile | IMPORT | 4 |
| 103776 | kernel32.lstrcmpiW | IMPORT | 2 |
| 103784 | kernel32.CreateToolhelp32Snapshot | IMPORT | 3 |
| 103792 | kernel32.GetCurrentProcessId | IMPORT | 3 |
| 103800 | kernel32.TerminateThread | IMPORT | 4 |
| 103808 | kernel32.SetLastError | IMPORT | 1 |
| 103816 | kernel32.HeapReAlloc | IMPORT | 1 |
| 103824 | kernel32.HeapAlloc | IMPORT | 1 |
| 103832 | kernel32.HeapFree | IMPORT | 1 |
| 103840 | kernel32.HeapDestroy | IMPORT | 1 |
| 103848 | kernel32.HeapCreate | IMPORT | 1 |
| 103856 | kernel32.ConnectNamedPipe | IMPORT | 1 |
| 103864 | kernel32.CreateNamedPipeW | IMPORT | 1 |
| 103872 | kernel32.DisconnectNamedPipe | IMPORT | 1 |
| 103880 | kernel32.FlushFileBuffers | IMPORT | 1 |
| 103888 | kernel32.lstrcpyW | IMPORT | 2 |
| 103896 | kernel32.CreateDirectoryW | IMPORT | 1 |
| 103904 | kernel32.lstrcmpW | IMPORT | 1 |
| 103912 | kernel32.Process32FirstW | IMPORT | 3 |
| 103920 | kernel32.Process32NextW | IMPORT | 3 |
| 103928 | kernel32.GetWindowsDirectoryW | IMPORT | 4 |
| 103936 | kernel32.DeleteFileW | IMPORT | 3 |
| 103944 | kernel32.GetComputerNameA | IMPORT | 1 |
| 103952 | kernel32.GetExitCodeProcess | IMPORT | 1 |
| 103960 | kernel32.GetTempFileNameW | IMPORT | 4 |
| 103968 | kernel32.CreateMutexW | IMPORT | 1 |
| 103976 | kernel32.GetTempPathW | IMPORT | 8 |
| 103984 | kernel32.MoveFileW | IMPORT | 1 |
| 103992 | kernel32.GetExitCodeThread | IMPORT | 2 |
| 104000 | kernel32.MapViewOfFile | IMPORT | 1 |
| 104008 | kernel32.UnmapViewOfFile | IMPORT | 2 |
| 104016 | kernel32.CreateRemoteThread | IMPORT | 1 |
| 104024 | kernel32.FlushInstructionCache | IMPORT | 1 |
| 104032 | kernel32.IsWow64Process | IMPORT | 1 |
| 104040 | kernel32.CreateFileMappingW | IMPORT | 1 |
| 104048 | kernel32.TerminateProcess | IMPORT | 6 |
| 104056 | kernel32.GetVersionExW | IMPORT | 1 |
| 104064 | kernel32.SizeofResource | IMPORT | 1 |
| 104072 | kernel32.WideCharToMultiByte | IMPORT | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 100318 | sub_1800193de |
| 39648 | sub_18000a6e0 |
| 36832 | sub_180009be0 |
| 30240 | sub_180008220 |
| 30416 | sub_1800082d0 |
| 78544 | sub_180013ed0 |
| 3872 | sub_180001b20 |
| 65472 | sub_180010bc0 |
| 63280 | sub_180010330 |
| 62544 | sub_180010050 |
| 64880 | sub_180010970 |
| 68192 | sub_180011660 |
| 75536 | sub_180013310 |
| 26304 | sub_1800072c0 |
| 32240 | sub_1800089f0 |
| 76112 | sub_180013550 |
| 47808 | sub_18000c6c0 |
| 35472 | sub_180009690 |
| 68656 | sub_180011830 |
| 85312 | sub_180015940 |
| 46288 | sub_18000c0d0 |
| 1856 | sub_180001340 |
| 98704 | sub_180018d90 |
| 27120 | sub_1800075f0 |
| 49072 | sub_18000cbb0 |
| 80864 | sub_1800147e0 |
| 46752 | sub_18000c2a0 |
| 38560 | sub_18000a2a0 |
| 52544 | sub_18000d940 |
| 49808 | sub_18000ce90 |

### Decompilations (top 6)
#### 100318 — sub_1800193de
```c

/* WARNING: Removing unreachable block (ram,0x000180019415) */
/* WARNING: Removing unreachable block (ram,0x000180019400) */
/* WARNING: Removing unreachable block (ram,0x0001800193eb) */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_1800193de(undefined4 *param_1)

{
    undefined4 *puVar1;
    undefined4 uVar2;
    undefined4 uVar3;
    undefined4 uVar4;
    undefined8 in_RAX;
    undefined4 *puVar5;
    
    puVar1 = cpuid_brand_part1_info(0x80000002);
    uVar2 = puVar1[1];
    uVar3 = puVar1[2];
    uVar4 = puVar1[3];
    *param_1 = *puVar1;
    param_1[1] = uVar2;
    param_1[2] = uVar4;
    param_1[3] = uVar3;
    puVar5 = param_1 + 0x10;
    puVar1 = cpuid_brand_part2_info(0x80000003);
    uVar2 = puVar1[1];
    uVar3 = puVar1[2];
    uVar4 = puVar1[3];
    *puVar5 = *puVar1;
    puVar5[1] = uVar2;
    puVar5[2] = uVar4;
    puVar5[3] = uVar3;
    puVar5 = param_1 + 0x20;
    puVar1 = cpuid_brand_part3_info(0x80000004);
    uVar2 = puVar1[1];
    uVar3 = puVar1[2];
    uVar4 = puVar1[3];
    *puVar5 = *puVar1;
    puVar5[1] = uVar2;
    puVar5[2] = uVar4;
    puVar5[3] = uVar3;
    return in_RAX;
}

```
#### 39648 — sub_18000a6e0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_18000a6e0(undefined8 *param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    int32_t *piVar4;
    int32_t iVar5;
    uint32_t uVar6;
    undefined *puVar7;
    int64_t iVar8;
    uint32_t uVar9;
    int64_t iVar10;
    undefined4 auStack_151 [2];
    undefined8 uStack_148;
    undefined8 uStack_140;
    undefined8 uStack_138;
    undefined8 uStack_130;
    int32_t aiStack_128 [64];
    
    uStack_148 = *param_1;
    uStack_140 = param_1[1];
    uStack_138 = param_1[2];
    uStack_130 = param_1[3];
    iVar8 = 0x10;
    puVar7 = param_1 + 0x29;
    do {
        iVar8 = iVar8 + -1;
        *(puVar7 + 4 + &stack0xfffffffffffffeab + -param_1) =
             CONCAT31(CONCAT21(CONCAT11(puVar7[-1], *puVar7), puVar7[1]), puVar7[2]);
        puVar7 = puVar7 + 4;
    } while (iVar8 != 0);
    piVar4 = aiStack_128;
    iVar8 = 0xc;
    do {
        uVar9 = piVar4[1];
        uVar1 = piVar4[2];
        uVar6 = piVar4[0xe];
        uVar2 = piVar4[3];
        uVar3 = piVar4[0xf];
        uVar6 = ((uVar6 << 0xf | uVar6 >> 0x11) ^ (uVar6 << 0xd | uVar6 >> 0x13) ^ uVar6 >> 10) +
                ((uVar9 << 0xe | uVar9 >> 0x12) ^ (uVar9 >> 7 | uVar9 << 0x19) ^ uVar9 >> 3) + piVar4[9] + *piVar4;
        piVar4[0x10] = uVar6;
        uVar9 = ((uVar3 << 0xf | uVar3 >> 0x11) ^ (uVar3 << 0xd | uVar3 >> 0x13) ^ uVar3 >> 10) +
                ((uVar1 << 0xe | uVar1 >> 0x12) ^ (uVar1 >> 7 | uVar1 << 0x19) ^ uVar1 >> 3) + piVar4[10] + uVar9;
        piVar4[0x11] = uVar9;
        piVar4[0x12] = ((uVar6 * 0x8000 | uVar6 >> 0x11) ^ (uVar6 * 0x2000 | uVar6 >> 0x13) ^ uVar6 >> 10) +
                       ((uVar2 << 0xe | uVar2 >> 0x12) ^ (uVar2 >> 7 | uVar2 << 0x19) ^ uVar2 >> 3) + piVar4[0xb] +
                       uVar1;
        uVar1 = piVar4[4];
        piVar4[0x13] = ((uVar9 * 0x8000 | uVar9 >> 0x11) ^ (uVar9 * 0x2000 | uVar9 >> 0x13) ^ uVar9 >> 10) +
                       ((uVar1 << 0xe | uVar1 >> 0x12) ^ (uVar1 >> 7 | uVar1 << 0x19) ^ uVar1 >> 3) + piVar4[0xc] +
                       uVar2;
        piVar4 = piVar4 + 4;
        iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    iVar8 = 0;
    do {
        iVar5 = ((uStack_138 >> 0xb | uStack_138 << 0x15) ^ (uStack_138 << 7 | uStack_138 >> 0x19) ^
                (uStack_138 >> 6 | uStack_138 << 0x1a)) + (~uStack_138 & uStack_130 ^ uStack_138._4_4_ & uStack_138) +
                *(&SHA256 + iVar8) + *(aiStack_128 + iVar8) + uStack_130._4_4_;
        uStack_130._4_4_ = uStack_140._4_4_ + iVar5;
        uStack_140._4_4_ =
             ((uStack_148 >> 0xd | uStack_148 << 0x13) ^ (uStack_148 << 10 | uStack_148 >> 0x16) ^
             (uStack_148 >> 2 | uStack_148 << 0x1e)) +
             ((uStack_148._4_4_ ^ uStack_148) & uStack_140 ^ uStack_148._4_4_ & uStack_148) + iVar5;
        iVar5 = ((uStack_130._4_4_ >> 0xb | uStack_130._4_4_ * 0x200000) ^
                 (uStack_130._4_4_ * 0x80 | uStack_130._4_4_ >> 0x19) ^
                (uStack_130._4_4_ >> 6 | uStack_130._4_4_ * 0x4000000)) +
                (~uStack_130._4_4_ & uStack_138._4_4_ ^ uStack_138 & uStack_130._4_4_) + *(iVar8 + 0x18001aa94) +
                *(aiStack_128 + iVar8 + 4) + uStack_130;
        uStack_130._0_4_ = uStack_140 + iVar5;
        uStack_140._0_4_ =
             ((uStack_140._4_4_ >> 0xd | uStack_140._4_4_ * 0x80000) ^
              (uStack_140._4_4_ * 0x400 | uStack_140._4_4_ >> 0x16) ^
             (uStack_140._4_4_ >> 2 | uStack_140._4_4_ * 0x40000000)) +
             ((uStack_148 ^ uStack_140._4_4_) & uStack_148._4_4_ ^ uStack_148 & uStack_140._4_4_) + iVar5;
        iVar10 = iVar8 + 0x10;
        iVar5 = ((uStack_130 >> 0xb | uStack_130 * 0x200000) ^ (uStack_130 * 0x80 | uStack_130 >> 0x19) ^
                (uStack_130 >> 6 | uStack_130 * 0x4000000)) + (~uStack_130 & uStack_138 ^ uStack_130._4_4_ & uStack_130)
                + *(iVar8 + 0x18001aa98) + *(aiStack_128 + iVar8 + 8) + uStack_138._4_4_;
        uStack_138._4_4_ = uSt
```
#### 36832 — sub_180009be0
```c

/* WARNING: Removing unreachable block (ram,0x000180009c40) */

/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_180009be0(int64_t param_1)

{
    int32_t iVar1;
    uint32_t uVar2;
    undefined4 uVar3;
    uint64_t uVar4;
    int64_t iVar5;
    int64_t iVar6;
    undefined4 auStackX_8 [2];
    int32_t aiStackX_10 [2];
    undefined4 auStackX_18 [4];
    undefined auStack_128 [256];
    
    *(param_1 + 0x188) = 0;
    iVar1 = sub_1800095b0();
    if (iVar1 == 0) {
        uVar4 = (*kernel32.GetLastError)();
        return uVar4;
    }
    uVar2 = 0x4000000;
    if ((*(param_1 + 0x98) & 1) != 0) {
        uVar2 = 0x4803000;
    }
    uVar4 = 0;
    iVar5 = (*wininet.HttpOpenRequestA)(*(param_1 + 0x10), 0x18001ad04, *(param_1 + 0xb0), 0, 0, 0, uVar2, 0);
    if (iVar5 == 0) {
        uVar4 = (*kernel32.GetLastError)();
    }
    else {
        if ((uVar2 >> 0x17 & 1) != 0) {
            sub_180008fa0(iVar5);
        }
        sub_180009000(iVar5);
        iVar1 = (*wininet.HttpSendRequestA)(iVar5, 0, 0, 0, uVar4 & 0xffffffff00000000);
        if (iVar1 == 0) {
            uVar2 = (*kernel32.GetLastError)();
            uVar4 = uVar2;
            (*wininet.InternetCloseHandle)(iVar5);
        }
        else {
            auStackX_8[0] = 0;
            iVar1 = (*wininet.InternetQueryDataAvailable)(iVar5, auStackX_8, 0, 0);
            uVar4 = 0;
            if ((iVar1 != 0) && (iVar6 = sub_18000a210(auStackX_8[0]), uVar4 = 0, iVar6 != 0)) {
                aiStackX_10[0] = 0;
                iVar1 = (*wininet.InternetReadFile)(iVar5, iVar6, auStackX_8[0], aiStackX_10);
                while( true ) {
                    uVar4 = 0;
                    if ((iVar1 == 0) || (uVar4 = 0, aiStackX_10[0] == 0)) goto code_r0x000180009d87;
                    iVar1 = sub_180008960(param_1 + 0x170, iVar6);
                    if (iVar1 == 0) break;
                    iVar1 = (*wininet.InternetReadFile)(iVar5, iVar6, auStackX_8[0], aiStackX_10);
                }
                uVar4 = 0x54f;
code_r0x000180009d87:
                sub_18000a250(iVar6);
            }
            auStackX_18[0] = 0x100;
            iVar1 = (*wininet.HttpQueryInfoW)(iVar5, 0x13, auStack_128, auStackX_18, 0);
            if (iVar1 != 0) {
                uVar3 = (*shlwapi.StrToIntW)(auStack_128);
                *(param_1 + 0x188) = uVar3;
            }
            (*wininet.InternetCloseHandle)(iVar5);
        }
    }
    return uVar4;
}

```

### Virtual Files (8)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| RCDATA/3DFRM0TFI/en-us | 54615 | - |
| RCDATA/4FGGN9GAK/en-us | 65220 | - |
| RCDATA/5GBYB8BZ3/en-us | 48 | - |
| RCDATA/6BNUV7NZJ/en-us | 160 | - |
| RCDATA/7MCIC6HXH/en-us | 1184 | - |
| RCDATA/8ZSYOX5YG/en-us | 5780 | - |
| RCDATA/9P3PS4UEF/en-us | 6863 | - |
| MANIF/2/en-us | 346 | - |

### Structures (67)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 224 |
| OptionalHeader | 248 |
| Sections | 488 |
| advapi32.FT | 103424 |
| iphlpapi.FT | 103680 |
| kernel32.FT | 103696 |
| netapi32.FT | 104336 |
| shell32.FT | 104368 |
| shlwapi.FT | 104400 |
| user32.FT | 104456 |
| userenv.FT | 104552 |
| wininet.FT | 104584 |
| ws2_32.FT | 104720 |
| bcrypt.FT | 104944 |
| ntdll.FT | 105032 |
| ImportTable | 120580 |
| advapi32.OFT | 120840 |
| iphlpapi.OFT | 121096 |
| kernel32.OFT | 121112 |
| netapi32.OFT | 121752 |
| shell32.OFT | 121784 |
| shlwapi.OFT | 121816 |
| user32.OFT | 121872 |
| userenv.OFT | 121968 |
| wininet.OFT | 122000 |
| ws2_32.OFT | 122136 |
| bcrypt.OFT | 122360 |
| ntdll.OFT | 122448 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 74 · duration_s: 1.01

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using Base64 | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.001:Encode Data |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| manually build AES constants | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| get socket status | T1016:System Network Configuration Discovery | C0001.012:Socket Communication |
| encode data using ADD XOR SUB operations | T1027:Obfuscated Files or Information | E1027.m03:Obfuscated Files or Information |
| create new key via CryptAcquireContext | T1027:Obfuscated Files or Information | C0028:Encryption Key |
| hash data via BCrypt | T1027:Obfuscated Files or Information | C0029:Cryptographic Hash |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get hostname | T1082:System Information Discovery | E1082:System Information Discovery |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| query or enumerate registry key | T1012:Query Registry | C0036.005:Registry |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| stop service | T1543.003:Create or Modify System Process, T1489:Service Stop |  |

## PE Imports / Signals
import_count: 192

| label | api_match | ATT&CK |
|---|---|---|
| create_remote_thread | CreateRemoteThread | T1055 |
| http_client | InternetOpen | T1071.001 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| get_proc_address | GetProcAddress | T1129 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 26

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@106664 len=7; $ipv6@135082 len=2 |
| contains_base64 | - | $a@43498 len=12 |
| Browsers | - | $ie@109464 len=24; $ff@109440 len=22; $chrome@109416 len=20 |
| Dropper_Strings | - | $a1@108846 len=52 |
| Misc_Suspicious_Strings | - | $a4@104200 len=14 |
| Advapi_Hash_API | - | $advapi32@104456 len=24; $CryptCreateHash@120804 len=15; $CryptHashData@120914 len=13; $CryptAcquireContext@120654 len=19 |
| SHA2_BLAKE2_IVs | - | $c0@40612 len=4; $c1@40619 len=4; $c2@40626 len=4; $c3@40633 len=4; $c4@40640 len=4; $c5@40651 len=4; $c6@40658 len=4; $c7@40665 len=4 |
| url | - | $url_regex@108232 len=20 |
| IsPE64 | - |  |
| IsDLL | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@192 len=4 |
| Microsoft_Visual_Cpp_80_DLL | - | $b@3136 len=4 |
| network_http | - | $f1@120296 len=11; $c1@119952 len=15; $c2@120194 len=12; $c3@120278 len=15; $c4@120048 len=16; $c5@120068 len=17; $c6@120128 len=15; $c7@119996 len=15 |
| network_tcp_socket | - | $f1@120518 len=10; $c1@120380 len=9; $c3@109064 len=4; $c4@120370 len=7; $c5@120356 len=10; $c6@122633 len=7 |
| escalate_priv | - | $d1@121244 len=12; $c2@120858 len=21 |
| win_mutex | - | $c1@122852 len=11 |
| win_registry | - | $f1@121244 len=12; $c3@120882 len=11; $c6@120882 len=11 |
| win_token | - | $f1@121244 len=12; $c1@121040 len=16; $c2@120858 len=21; $c3@120634 len=16 |
| win_files_operation | - | $f1@123034 len=12; $c1@120076 len=9; $c3@120076 len=9; $c4@120056 len=8 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@120518 len=10 |
| Str_Win32_Wininet_Library | - | $wininet_lib@120296 len=11 |
| Str_Win32_Internet_API | - | $wininet_call_closeh@120228 len=19; $wininet_call_readf@120048 len=16; $wininet_call_connect@119952 len=15; $wininet_call_open@120194 len=12 |
| Str_Win32_Http_API | - | $wininet_call_httpr@119996 len=15; $wininet_call_httpq@120110 len=13; $wininet_call_httpo@120128 len=15 |

## Generated YARA Meta
```json
{
  "sha256": "8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde",
  "family": "trojan.dyreza/battdil",
  "imphash": "8d7e3e41cd993d5a41f4e96d6076c4f7",
  "generated_at": "2026-08-12T18:18:50.178442+00:00",
  "string_count": 24,
  "strings": [
    "=&&jL66Zl??A~",
    "&jL&6Zl6?A~?",
    "jL&&Zl66A~??",
    "L&&jl66Z~??A",
    "unknown_64bit",
    "daYdnceM",
    "daYdnceMm",
    "daYdnceMmb",
    "daYdnceMmbN",
    "daYdnceMmbNJ",
    "daYdnceMmbNJX",
    "daYdnceMmbNJXp",
    "daYdnceMmbNJXpF",
    "daYdnceMmbNJXpFB",
    "daYdnceMmbNJXpFBN",
    "daYdnceMmbNJXpFBNX",
    "daYdnceMmbNJXpFBNXc",
    "daYdnceMmbNJXpFBNXci",
    "daYdnceMmbNJXpFBNXciG",
    "daYdnceMmbNJXpFBNXciGG",
    "daYdnceMmbNJXpFBNXciGGe",
    "daYdnceMmbNJXpFBNXciGGeW",
    "daYdnceMmbNJXpFBNXciGGeWm",
    "daYdnceMmbNJXpFBNXciGGeWmS"
  ],
  "rule_path": "/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/rule.yar",
  "sigma_path": "/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/rule.yml",
  "iocs_path": "/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/iocs.json",
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
    "utc": "2026-08-12 18:18:50 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 907 · per_category: `{"decoded_strings": 89, "stack_strings": 0, "tight_strings": 1, "language_strings": 0, "language_strings_missed": 0, "static_strings": 817}`

### FLOSS sample
- `=&&jL66Zl??A~`
- `&jL&6Zl6?A~?`
- `jL&&Zl66A~??`
- `L&&jl66Z~??A`
- `j:,4;87`
- `unknown_64bit`
- `daYdnc`
- `daYdnce`
- `daYdnceM`
- `daYdnceMm`
- `daYdnceMmb`
- `daYdnceMmbN`
- `daYdnceMmbNJ`
- `daYdnceMmbNJX`
- `daYdnceMmbNJXp`
- `daYdnceMmbNJXpF`
- `daYdnceMmbNJXpFB`
- `daYdnceMmbNJXpFBN`
- `daYdnceMmbNJXpFBNX`
- `daYdnceMmbNJXpFBNXc`
- `daYdnceMmbNJXpFBNXci`
- `daYdnceMmbNJXpFBNXciG`
- `daYdnceMmbNJXpFBNXciGG`
- `daYdnceMmbNJXpFBNXciGGe`
- `daYdnceMmbNJXpFBNXciGGeW`
- `daYdnceMmbNJXpFBNXciGGeWm`
- `daYdnceMmbNJXpFBNXciGGeWmS`
- `daYdnceMmbNJXpFBNXciGGeWmSx`
- `daYdnceMmbNJXpFBNXciGGeWmSxB`
- `daYdnceMmbNJXpFBNXciGGeWmSxBe`
- `daYdnceMmbNJXpFBNXciGGeWmSxBeP`
- `daYdnceMmbNJXpFBNXciGGeWmSxBePk`
- `daYdnceMmbNJXpFBNXciGGeWmSxBePkF`
- `daYdnceMmbNJXpFBNXciGGeWmSxBePkFp`
- `daYdnceMmbNJXpFBNXciGGeWmSxBePkFpN`
- `daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNP`
- `daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPq`
- `daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPqu`
- `daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquU`
- `daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUk`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x1800146b0
```asm
┌ 42: entry0 (int64_t arg1, int64_t arg2);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           0x1800146b0      4883ec28       sub rsp, 0x28
│           0x1800146b4      85d2           test edx, edx              ; arg2
│       ┌─< 0x1800146b6      7413           je 0x1800146cb
│       │   0x1800146b8      ffca           dec edx                    ; arg2
│      ┌──< 0x1800146ba      7514           jne 0x1800146d0
│      ││   0x1800146bc      e84f390000     call fcn.180018010
│      ││   0x1800146c1      b801000000     mov eax, 1
│      ││   0x1800146c6      4883c428       add rsp, 0x28
│      ││   0x1800146ca      c3             ret
│      │└─> 0x1800146cb      e8c0390000     call fcn.180018090
│      └──> 0x1800146d0      b801000000     mov eax, 1
│           0x1800146d5      4883c428       add rsp, 0x28
└           0x1800146d9      c3             ret
```
### 0x180018010
```asm
│╎╎╎   ; CALL XREF from entry0 @ 0x1800146bc(x)
┌ 875: fcn.180018010 (int64_t arg1);
│    │╎╎╎   ; arg int64_t arg1 @ rcx
│    │╎╎╎   ; var int64_t var_20h @ rsp+0x20
│    │╎╎╎   ; var int64_t var_28h @ rsp+0x28
│    │╎╎╎   ; var int64_t var_30h @ rsp+0x30
│    │╎╎╎   ; var int64_t var_38h @ rsp+0x38
│    │╎╎╎   ; var int64_t var_40h @ rsp+0x40
│    │╎╎╎   ; var int64_t var_1e0h @ rsp+0x1e0
│    │╎╎╎   ; var int64_t var_1e8h @ rsp+0x1e8
│    │╎╎╎   ; var int64_t var_200h @ rsp+0x200
│    │╎╎╎   ; var int64_t var_208h @ rsp+0x208
│    │╎╎╎   ; var int64_t var_210h @ rsp+0x210
│    │╎╎╎   ; var int64_t var_218h @ rsp+0x218
│    └────< 0x180018010      e98bfcffff     jmp 0x180017ca0
..
│     ╎╎╎   ; CODE XREF from fcn.180018090 @ 0x180018090(x)
     │ ╎╎   ; CALL XREF from entry0 @ 0x1800146cb(x)
       │    ; CALL XREFS from fcn.180018010 @ 0x180017f9d(x), 0x180017fb9(x), 0x180017fd5(x)
       │    ; CALL XREFS from fcn.180018090 @ 0x180018051(x), 0x18001806d(x)
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
- hook_candidates:
  - `IPHLPAPI.DLL!GetAdaptersAddresses`
  - `WININET.dll!InternetConnectA`
  - `WININET.dll!HttpSendRequestExW`
  - `WININET.dll!InternetQueryDataAvailable`
  - `WININET.dll!InternetReadFile`
  - `WININET.dll!InternetWriteFile`
  - `WS2_32.dll!WSAConnect`
  - `WS2_32.dll!htons`
  - `WS2_32.dll!select`
  - `WS2_32.dll!WSACreateEvent`
  - `WS2_32.dll!closesocket`
  - `SHLWAPI.dll!StrToIntA`
  - `SHLWAPI.dll!StrTrimA`
  - `SHLWAPI.dll!StrStrIA`
  - `SHLWAPI.dll!StrToIntW`
  - `SHLWAPI.dll!StrStrIW`
  - `ADVAPI32.dll!OpenProcessToken`
  - `ADVAPI32.dll!RegEnumKeyExW`
  - `ADVAPI32.dll!RegOpenKeyW`
  - `ADVAPI32.dll!QueryServiceConfigW`
  - `ADVAPI32.dll!ControlService`
  - `USERENV.dll!CreateEnvironmentBlock`
  - `USERENV.dll!DestroyEnvironmentBlock`
  - `USERENV.dll!LoadUserProfileW`
  - `bcrypt.dll!BCryptOpenAlgorithmProvider`
  - `bcrypt.dll!BCryptDestroyHash`
  - `bcrypt.dll!BCryptHashData`
  - `bcrypt.dll!BCryptFinishHash`
  - `bcrypt.dll!BCryptVerifySignature`
  - `NETAPI32.dll!NetApiBufferFree`

## Audit Trail (recent)
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786558730.0692084}`
- `{"source": "yara_gen_v2", "ts": 1786558730.1786115}`
- `{"source": "publish_report_v2", "ts": 1786558886.3308015}`
- `{"source": "publish_report_v2_technical", "ts": 1786559165.1835208}`
- `{"source": "publish_report_v2", "ts": 1786594893.4323509}`
- `{"source": "publish_report_v2_technical", "ts": 1786595447.9370627}`
- `{"source": "publish_report_v2", "ts": 1786608638.1234434}`
- `{"source": "publish_report_v2_technical", "ts": 1786608998.9963007}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786675048.732784}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786675048.7363698}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786675048.7398083}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786675048.7432926}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs LIMIT 15", "ts": 1786675048.745787}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786675054.8104627}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786675055.3384008}`
- `{"source": "ghidra_query", "sql": "SELECT name, addr FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1786675056.1054869}`
- `{"source": "ghidra_query", "sql": "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786675056.7804341}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786675057.3478365}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786675057.8545127}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786675060.7195566}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786675061.1208503}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786675062.234793}`
- `{"source": "ghidra_query", "sql": "SELECT addr, content FROM strings WHERE length < 300", "ts": 1786675062.756409}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786675063.2836864}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786675063.673056}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786675064.6946926}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786675065.6998525}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786675068.4733047}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786675068.8587162}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786675068.8629222}`
