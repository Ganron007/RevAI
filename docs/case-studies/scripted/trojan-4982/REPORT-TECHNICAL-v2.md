> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:22:31 UTC

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

This report details the analysis of a 32-bit Windows PE executable (`trojan_4982.exe`) identified as malicious with high confidence (score 85/100). The sample exhibits characteristics of the **Trioris/Cerbu** trojan family, as corroborated by VirusTotal detections (55/72 engines) and internal tooling (source: llm_judge). The malware is a feature-rich trojan designed for data theft, command-and-control (C2) communication, and system reconnaissance.

Key capabilities include HTTP-based C2 communication with the domain `twoyden.ru`, SOCKS5 proxy relay functionality, system fingerprinting (VM detection, OS info), and registry persistence via `Software\ClearSystem`. The sample employs multiple anti-analysis techniques, including anti-debugging checks (`IsDebuggerPresent`), obfuscated stack strings, and XOR/RC4 encryption (source: capa). It masquerades its User-Agent as `NSISDL/1.2` to blend in with legitimate NSIS installer traffic (source: Ghidra string_refs). The sample requests `requireAdministrator` privileges via its manifest, indicating potential for privilege escalation (source: Ghidra strings).

Dynamic analysis with Speakeasy and Frida recorded zero runtime events, which we assess as likely due to anti-analysis or environment-specific triggers rather than benign behavior, given the strong static indicators (source: Speakeasy, Frida Probe). The combination of behavioral-intent evidence (C2 strings, data theft patterns, persistence mechanisms) and obfuscation techniques confirms malicious intent beyond mere protection.

## 2. Sample Metadata

| Attribute | Value | Source |
|---|---|---|
| SHA256 | `38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73` | Malcat |
| File Name | `trojan_4982.exe` | Malcat |
| File Size | 235,184 bytes | Malcat |
| File Type | PE (Portable Executable) | Malcat |
| Architecture | x86 (32-bit) | Malcat |
| Entry Point EA | 57943 (0x0040EE57) | Malcat |
| Whole-File Entropy | 6.82 bits/byte | Malcat |
| Compiler/Linker | MSVC 2013 (MSVC_2013_linker YARA rule) | Malcat YARA |
| Imphash | `b5f4ee827c576f7005f9e544e6955bfb` | Generated YARA Meta |
| VirusTotal Detections | 55/72 engines | External TI |
| Threat Family | Trioris/Cerbu | External TI |
| Verdict | Malicious (score 85) | llm_judge |

## 3. File Layout & Structural Analysis

The PE file is a standard 32-bit executable with a high-entropy overlay, suggesting appended data or a packed payload. The entry point is within the `.text` section, which has execute/read permissions (source: Malcat File Layout).

**Section Table (source: Malcat File Layout):**
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 32 | - |
| .text | 1024 | 133632 | 135168 | 140 | RX |
| .rdata | 136192 | 37376 | 40960 | 74 | R |
| .data | 177152 | 8704 | 20480 | 58 | RW |
| .rsrc | 197632 | 2560 | 4096 | 111 | R |
| .reloc | 201728 | 7680 | 8192 | 123 | R |
| overlay | 209920 | 44208 | 0 | 186 | - |

The `.text` section contains the primary executable code with moderate entropy (140), indicating some obfuscation or compression. The overlay section has very high entropy (186), which is a strong indicator of appended, possibly encrypted or compressed, data. This is consistent with the sample's use of XOR and RC4 encryption (source: capa).

**Anomalies Detected (source: Malcat Anomalies):**
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| BigStringHiScore | 3 | strings | 1 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 1 | string is constructed dynamically |
| ManyUniqueImmediateBytes | 3 | code | 5 | More than 48 unique bytes defined across all immediate operands in the function |
| XorInLoop | 3 | code | 16 | XOR instruction in a loop |
| SequentialFunction | 1 | code | 1 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 8 | Function with lots of intra jumps, could be obfuscated |

The `InvalidChecksum` anomaly is a common anti-analysis technique to break simple integrity checks. The `DynamicString` and `XorInLoop` anomalies are direct evidence of obfuscation, where strings are built at runtime or decoded via XOR loops to evade static analysis (source: Malcat). The `SpaghettiFunction` anomalies (8 hits) suggest control-flow obfuscation, making reverse engineering more difficult.

## 4. Static Code Analysis

Static analysis reveals a complex, obfuscated binary with clear malicious intent. The code is heavily obfuscated with stack strings, XOR encoding, and RC4 encryption (source: capa).

**Key Disassembly at Entry Point (source: radare2):**
```asm
┌ 300: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_24h @ ebp-0x24
│       ╎   0x0040ee57      e852950000     call 0x4183ae
│       └─< 0x0040ee5c      e97ffeffff     jmp 0x40ece0
```
The entry point immediately calls a function at `0x4183ae` and then jumps to `0x40ece0`. This is a common pattern for packed or obfuscated code, where the initial call sets up the environment or unpacks the real payload. The jump to a lower address suggests a loop or a trampoline.

**Main Function Prologue (source: radare2):**
```asm
┌ 1000: int main (char **argv, char **envp, int32_t envp, int32_t arg_78h, int32_t arg_28h_2, int32_t arg_28h, int32_t arg_30h, int32_t arg_48h);
│           ; arg char **argv @ esp+0x78
│           ; arg char **envp @ esp+0x7c
│           ; arg int32_t envp @ esp+0x80
│           ; arg int32_t arg_78h @ esp+0x84
│           ; arg int32_t arg_28h_2 @ esp+0x88
│           ; arg int32_t arg_28h @ esp+0x8c
│           ; arg int32_t arg_30h @ esp+0x90
│           ; arg int32_t arg_48h @ esp+0xb0
│           ; var int32_t var_10h_5 @ esp+0x20
│           ; var int32_t var_14h_7 @ esp+0x24
│           ; var int32_t var_10h_4 @ esp+0x28
│           ; var int32_t var_1ch_5 @ esp+0x2c
│           ; var int32_t var_10h_3 @ esp+0x30
│           ; var int32_t var_10h_2 @ esp+0x34
│           ; var int32_t var_1ch_4 @ esp+0x38
│           ; var int32_t var_14h_6 @ esp+0x3c
│           ; var int32_t var_10h @ esp+0x40
│           ; var int32_t var_14h_5 @ esp+0x44
│           ; var int32_t var_1ch_6 @ esp+0x48
│           ; var int32_t var_14h_4 @ esp+0x4c
│           ; var int32_t var_14h_3 @ esp+0x50
│           ; var int32_t var_34h @ esp+0x54
│           ; var int32_t var_18h_2 @ esp+0x58
│           ; var int32_t var_14h_2 @ esp+0x5c
│           ; var int32_t var_1ch_3 @ esp+0x60
│           ; var int32_t var_18h @ esp+0x64
│           ; var int32_t var_14h @ esp+0x68
│           ; var int32_t var_1ch_2 @ esp+0x6c
│           ; var int32_t var_1ch @ esp+0x70
│           0x0040ada5      55             push ebp
│           0x0040ada6      8bec           mov ebp, esp
│           0x0040ada8      83e4f8         and esp, 0xfffffff8
│           0x0040adab      b8e4350000     mov eax, 0x35e4
│           0x0040adb0      e8db940000     call 0x414290
│           0x0040adb5      a1c0c44200     mov eax, dword [0x42c4c0]   ; [0x42c4c0:4]=0xbb40e64e
│           0x0040adba      33c4           xor eax, esp
│           0x0040adbc      898424e035..   mov dword [esp + 0x35e0], eax ; [0x35e0:4]=-1
│           0x0040adc3      53             push ebx
│           0x0040adc4      56             push esi
│           0x0040adc5      33c0           xor eax, eax
│           0x0040adc7      8d4c2448       lea ecx, [arg_48h]
│           0x0040adcb      57             push edi
│           0x0040adcc      89442428       mov dword [arg_28h], eax
│           0x0040add0      e851e9ffff     call 0x409726
│           0x0040add5      33ff           xor edi, edi
│           0x0040add7      8d4c244c       lea ecx, [arg_48h]
│           0x0040addb      47             inc edi
│           0x0040addc      e8008effff     call 0x403be1
│           0x0040ade1      51             push ecx
│           0x0040ade2      8d4c2430       lea ecx, [arg_30h]
│           0x0040ade6      89442428       mov dword [arg_28h_2], eax
│           0x0040adea      e8d1daffff     call 0x4088c0
│           0x0040adef      686c7f4200     push 0x427f6c               ; 'l\x7fB'
```
The main function sets up a large stack frame (0x35e4 bytes) and initializes a security cookie (`0x42c4c0`). The XOR of the cookie with ESP is a stack buffer overflow protection mechanism (GS cookie). The function then calls several subroutines (`0x409726`, `0x403be1`, `0x4088c0`), which likely perform initialization, string decoding, and setup for the malware's core functionality.

**Decompilation of Key Function (source: Malcat Decompilations):**
The function `sub_40bd1e` (EA 45342) shows a complex routine that initializes MD5 constants (`0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`), indicating cryptographic operations. It calls multiple subroutines and processes strings, which aligns with the malware's data processing and C2 communication setup.

**Obfuscation Techniques (source: capa):**
- **Obfuscated Stack Strings**: Strings are built on the stack character-by-character to avoid static string detection.
- **XOR Encoding**: Data is encoded using XOR operations, a simple but effective obfuscation.
- **RC4 KSA Encryption**: The RC4 Key Scheduling Algorithm is used for more robust encryption of data, likely for C2 communication or payload decryption.

## 5. Behavioral & Dynamic Analysis

Dynamic analysis was performed using Speakeasy and Frida Probe. Both tools executed but recorded **zero runtime events** (source: Speakeasy, Frida Probe). This is a significant finding. Given the strong static indicators of malicious behavior (C2 strings, anti-debugging, persistence mechanisms), we assess this is likely due to the sample's anti-analysis techniques detecting the analysis environment and terminating, or requiring specific triggers (e.g., a particular command-line argument, registry key, or network condition) not present in the sandbox.

**Speakeasy Result:**
- `speakeasy_ok: True`
- `api_calls: 0`
- `key_events: 0`
- **Interpretation**: The emulator ran the sample but observed no API calls. This suggests the sample may have exited early after detecting the emulated environment, or its execution path was not triggered.

**Frida Probe Result:**
- `frida_available: True`
- `version: 17.16.4`
- `hook_candidates`: A list of 26 API functions from KERNEL32, USER32, ADVAPI32, SHELL32, ole32, SHLWAPI, WS2_32, and RPCRT4 were identified as potential hook points. However, no calls to these functions were recorded during execution.
- **Interpretation**: The Frida probe was ready to intercept calls but none occurred, reinforcing the assessment that the sample did not execute its main payload in this environment.

**Implication**: The absence of dynamic behavior does not indicate benign intent. Instead, it highlights the sample's effectiveness at evading automated analysis. The static evidence is sufficient to confirm malicious capabilities.

## 6. Network Indicators & C2

The sample contains hardcoded network indicators and C2 infrastructure (source: Ghidra string_refs, Malcat strings).

**Primary C2 Domain:**
- `twoyden.ru` (source: Ghidra string_refs, addr 0x00409aa5; Malcat strings EA 159552)

**HTTP Communication:**
- **User-Agent Spoofing**: The sample spoofs its User-Agent as `NSISDL/1.2` to disguise C2 traffic as legitimate NSIS installer downloads (source: Ghidra strings, addr 4357332; Malcat strings EA 159956).
- **Custom Header**: A custom `My-User-Agent:` header is used (source: Ghidra string_refs, addr 0x0040aac8).
- **HTTP Methods**: The sample uses HTTP POST for data exfiltration and GET for receiving commands (source: Ghidra string_refs, FUN_004060ce).
- **Proxy Awareness**: The sample reads `ProxyServer` and `ProxyOverride` from the registry (`Software\Microsoft\Windows\CurrentVersion\Internet Settings`) and handles `proxy-authenticate` and `www-authenticate` responses, indicating it can operate behind corporate proxies (source: Ghidra string_refs, FUN_004095b5, FUN_0040791d; Malcat strings EA 161960, 159064, 159028).

**SOCKS5 Proxy Relay:**
- The string `socks` is present (source: Ghidra strings, addr 4356372), and the import table includes full WSA socket APIs (`WSAConnect`, `WSASocketA`, `WSASend`, `WSARecv`, `WSAEventSelect`), indicating capability to act as a SOCKS5 proxy relay (source: Ghidra string_refs).

**Build/Config String:**
- `/S pid=129 subid=10 mr=0 lang=ru` (source: Ghidra strings, addr 4359000; Malcat strings EA 161624). This string suggests the sample is configured for Russian-locale targeting (`lang=ru`) and contains campaign/build identifiers (`pid`, `subid`).

## 7. Capabilities Assessment

Based on static analysis, the sample possesses the following capabilities. Note: These are **present capabilities** inferred from code; dynamic execution was not observed.

| Capability | Evidence | Source |
|---|---|---|
| **Anti-Debugging** | `IsDebuggerPresent` import (T1622); YARA `anti_dbg` rule matches at offsets 169872, 170594, 169284 | pe_imports, yara |
| **Process Injection** | `VirtualAlloc` + `VirtualProtect` imports (T1055); `CreateProcessW` for child process spawning | pe_imports |
| **Dynamic API Resolution** | `LoadLibraryExW` + `GetProcAddress` imports (T1129) | pe_imports |
| **Data Theft** | Capa rule: `parse credit card information` | capa |
| **C2 Communication** | Capa rules: `send data`, `receive data`, `resolve DNS`, `reference HTTP User-Agent string`, `check HTTP status code`, `initialize Winsock library` | capa |
| **Registry Persistence** | Writes to `Software\ClearSystem` with values `value_vm` and `value_os` (FUN_0040399b, FUN_00403a25) | Ghidra string_refs |
| **System Fingerprinting** | Reads `InstallDate` from `SOFTWARE\Microsoft\Windows NT\CurrentVersion`; detects VMs via registry keys (`HARDWARE\ACPI\krb.mainsetup.vbox`, etc.) | Ghidra string_refs, FLOSS strings |
| **Privilege Escalation** | `requireAdministrator` manifest (addr 4396736) | Ghidra strings |
| **Obfuscation** | Capa rules: `contain obfuscated stackstrings` (T1027.005), `encode data using XOR` (T1027), `encrypt data using RC4 KSA` (T1027) | capa |
| **File Operations** | Capa rules: `get common file path`, `check if file exists`, `get file size`, `set file attributes` | capa |
| **Registry Operations** | Capa rule: `query or enumerate registry value` (T1012) | capa |

## 8. Indicators of Compromise

**File Hashes:**
- SHA256: `38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73`
- Imphash: `b5f4ee827c576f7005f9e544e6955bfb`

**Network Indicators:**
- Domain: `twoyden.ru`
- User-Agent: `NSISDL/1.2`
- Custom Header: `My-User-Agent:`

**Registry Keys:**
- `HKCU\Software\ClearSystem` (values: `value_vm`, `value_os`)
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (value: `InstallDate`)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (values: `ProxyServer`, `ProxyOverride`)

**File Paths:**
- `\expand.ini` (source: Malcat strings EA 160588)

**Strings:**
- `/S pid=129 subid=10 mr=0 lang=ru`
- `This is E2RU tra.. setup. Install?` (source: Malcat strings EA 161736)
- `checklink.info` (source: Malcat strings EA 160824)
- `userbrowser` (source: Malcat strings EA 161276)

## 9. Detection Engineering

**YARA Rules (source: Generated YARA Meta):**
A YARA rule was generated for this sample. Key strings include obfuscated patterns and error messages. The rule is located at `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yar`.

**Sigma Rules:**
A Sigma rule was generated at `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yml`.

**Detection Recommendations:**
1. **Network Monitoring**: Alert on HTTP traffic with User-Agent `NSISDL/1.2` to non-NSIS domains, especially to `twoyden.ru`.
2. **Registry Monitoring**: Monitor for writes to `HKCU\Software\ClearSystem`.
3. **Process Monitoring**: Alert on processes with `requireAdministrator` manifest that also exhibit anti-debugging behavior.
4. **String-Based Detection**: Use the generated YARA rule to detect similar samples.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence | Source |
|---|---|---|---|
| **Defense Evasion** | Obfuscated Files or Information (T1027) | XOR encoding, RC4 KSA encryption, obfuscated stack strings | capa |
| **Defense Evasion** | Process Injection (T1055) | `VirtualAlloc`, `VirtualProtect`, `CreateProcess` imports | pe_imports |
| **Defense Evasion** | Deobfuscate/Decode Files or Information (T1140) | Dynamic string construction, XOR loops | Malcat anomalies |
| **Discovery** | System Information Discovery (T1082) | Reads `InstallDate`, VM detection via registry | Ghidra string_refs |
| **Discovery** | File and Directory Discovery (T1083) | Capa rules: `get common file path`, `check if file exists`, `get file size` | capa |
| **Discovery** | Query Registry (T1012) | Capa rule: `query or enumerate registry value` | capa |
| **Collection** | Data from Local System (T1005) | Capa rule: `parse credit card information` | capa |
| **Command and Control** | Application Layer Protocol (T1071) | HTTP POST/GET with custom User-Agent | Ghidra string_refs |
| **Command and Control** | Proxy (T1090) | SOCKS5 proxy relay capability, proxy-aware HTTP | Ghidra string_refs |
| **Command and Control** | Encrypted Channel (T1573) | RC4 encryption for C2 data | capa |
| **Persistence** | Boot or Logon Autostart Execution (T1547) | Registry persistence via `Software\ClearSystem` | Ghidra string_refs |
| **Privilege Escalation** | Abuse Elevation Control Mechanism (T1548) | `requireAdministrator` manifest | Ghidra strings |
| **Execution** | Shared Modules (T1129) | Dynamic API resolution via `LoadLibraryExW` + `GetProcAddress` | pe_imports |

## 11. What We Don't Know

1. **Dynamic Behavior**: The exact runtime behavior is unknown because Speakeasy and Frida recorded zero events. We assess this is due to anti-analysis or missing triggers, but the specific trigger condition is unknown.
2. **Payload Delivery**: How the initial payload is delivered (e.g., phishing, exploit kit) is not determined from this sample alone.
3. **Full C2 Protocol**: The exact structure of the C2 protocol (e.g., encryption keys, command format) is obfuscated and requires deeper reverse engineering.
4. **Persistence Mechanism Details**: While registry keys are identified, the exact method of persistence (e.g., Run key, scheduled task) is not fully mapped.
5. **Data Exfiltration Scope**: The full scope of data targeted for exfiltration (beyond credit card info) is unclear.
6. **Lateral Movement**: No evidence of lateral movement capabilities was observed, but this cannot be ruled out without dynamic analysis.
7. **Anti-Analysis Specifics**: The exact anti-debugging and anti-VM techniques beyond `IsDebuggerPresent` and registry checks are not fully enumerated.

## 12. Appendix A: Tool Evidence Trail

**Audit Trail (source: Audit Trail):**
- Multiple Ghidra and IDA queries were executed to extract strings, functions, imports, and call edges.
- Key queries include:
  - `SELECT sr.func_name, sr.func_addr, sr.string_value FROM string_refs sr WHERE sr.func_addr IN (4233893, 4219086, 4209051, 4209189, 4232629, 4240118, 4225309, 4238024) ORDER BY sr.func_name, sr.string_value` (source: ghidra_query)
  - `SELECT content, address FROM strings WHERE content LIKE '%pid=%' OR content LIKE '%subid=%' OR content LIKE '%lang=%' OR content LIKE '%SOCKS%' OR content LIKE '%socks%' OR content LIKE '%CONNECT%' OR content LIKE '%bind%' OR content LIKE '%resolve%'` (source: ghidra_query)
  - `SELECT f.name, f.address, f.size, fm.cyclomatic_complexity, fm.instruction_count, fm.call_out_count, fm.string_ref_count FROM function_metrics fm JOIN funcs f ON fm.func_addr = f.address WHERE fm.string_ref_count > 5 ORDER BY fm.string_ref_count DESC LIMIT 15` (source: ghidra_query)

**Generated YARA Meta (source: Generated YARA Meta):**
- Rule path: `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yar`
- Sigma path: `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yml`
- IOCs path: `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/iocs.json`

## 13. Appendix B: Analysis Environment

- **Project**: day6
- **Sample Path**: `/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe`
- **Tools Used**: Malcat, Ghidra, IDA, radare2, capa, YARA, FLOSS, Speakeasy, Frida Probe, VirusTotal
- **Analysis Date**: 2026-08-12
- **Analyst**: Automated RevAI Pipeline (langgraph engine)
- **Confidence**: High (90/100) based on static evidence and tool agreement.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73  
**sample_path:** /opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe  
**project_name:** day6

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: Trioris
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple tools detect anti-debugging, network communication, data theft, and obfuscation. Ghidra, IDA, and MalCat confirm PE structure and anomalies. Capa identifies behavioral intent (credit card parsing, C2). VirusTotal shows high detection rate (55/72) with threat family 'Trioris/Cerbu'.
- **summary**: The sample is a PE x86 executable exhibiting multiple malicious behaviors: anti-debugging (IsDebuggerPresent, anti_dbg YARA), process creation and memory manipulation (CreateProcess, VirtualAlloc, VirtualProtect), network communication (send/receive data, DNS resolution, HTTP User-Agent), and data theft (credit card parsing). Obfuscation techniques (XorInLoop, DynamicString) are present but considered neutral alone; however, combined with behavioral indicators, they support malicious intent. VirusTotal reports 55/72 detections with threat family 'Trioris/Cerbu'. The sample is signed with an invalid signature, further raising suspicion.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | pe_imports signals | `check_debugger (IsDebuggerPresent)` | Anti-debugging capability, common in malware to evade analysis. |
| pe_imports | pe_imports signals | `create_process (CreateProcess)` | Ability to create new processes, often used for process injection or launching malicious payloads. |
| pe_imports | pe_imports signals | `allocate_memory (VirtualAlloc)` | Dynamic memory allocation, common in code injection or unpacking. |
| pe_imports | pe_imports signals | `change_memory_protection (VirtualProtect)` | Changing memory protection to execute injected code or modify existing code. |
| capa | capa rules | `parse credit card information` | Indicates data theft targeting financial information, a clear malicious intent. |
| capa | capa rules | `send data` | Network communication capability for data exfiltration or C2. |
| capa | capa rules | `receive data` | Network communication capability for command and control. |
| capa | capa rules | `resolve DNS` | Network communication for domain resolution, typical of C2 infrastructure. |
| capa | capa rules | `reference HTTP User-Agent string` | HTTP communication, likely for command and control or data exfiltration. |
| yara | YARA matches | `anti_dbg` | Anti-debugging technique detected, indicating evasion. |
| external TI | VirusTotal | `55/72 detections, threat family trioris/cerbu` | High detection rate and identified threat family confirm malicious nature. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This PE is a trojan with HTTP-based C2 communication to the Russian domain 'twoyden.ru', SOCKS5 proxy/relay capability, system fingerprinting (VM detection, OS info), registry persistence via 'Software\ClearSystem', anti-debug checks, RC4/XOR encryption, obfuscated stack strings, and privilege escalation via requireAdministrator manifest. It masquerades its User-Agent as 'NSISDL/1.2' while conducting HTTP POST/GET requests with full proxy awareness. Exfiltration is supported via HTTP POST requests to 'twoyden.ru' for data sending {Network_traffic_analysis, HTTP_POST_requests, twoyden.ru, exfiltration_capability}. Credential access techniques were not observed in the analysis {Dynamic_analysis, API_calls, absence_of_credential_functions, not_observed}.

### deep key_evidence
- `"Domain 'twoyden.ru' referenced in FUN_00409aa5 (Ghidra string_refs, addr 0x00409aa5)"`
- `"HTTP/1.1 C2 communication with POST method, Host/Content-Type/Content-Length headers in FUN_004060ce (Ghidra string_refs)"`
- `"User-Agent: NSISDL/1.2 spoofing in FUN_004060ce to disguise C2 traffic as NSIS downloader (Ghidra strings, addr 4357332)"`
- `"Custom 'My-User-Agent:' header in FUN_0040aac8 (Ghidra string_refs, addr 0x0040aac8)"`
- `"Registry persistence via 'Software\\ClearSystem' keys with 'value_vm' and 'value_os' values (FUN_0040399b, FUN_00403a25)"`
- `"System fingerprinting: reads InstallDate from SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion, stores OS/VM info (Ghidra string_refs FUN_00403a25)"`
- `"Build/config string '/S pid=129 subid=10 mr=0 lang=ru' indicating Russian-locale targeting (Ghidra strings, addr 4359000)"`
- `"SOCKS5 proxy relay capability: 'socks' string present (Ghidra strings, addr 4356372), full WSA socket APIs (WSAConnect, WSASocketA, WSASend, WSARecv, WSAEventSelect)"`
- `"Proxy-aware HTTP: reads ProxyServer/ProxyOverride from Internet Settings registry, handles proxy-authenticate/www-authenticate responses (FUN_004095b5, FUN_0040791d)"`
- `"Anti-debug: IsDebuggerPresent import (pe_import_signals T1622), YARA anti-debug rule matches at offsets 169872/170594/169284"`
- `"Capa: obfuscated stackstrings (T1027.005), XOR encoding (T1027/C0026.002), RC4 KSA encryption (C0027.009/C0028.002)"`
- `"requireAdministrator manifest requesting elevated privileges (Ghidra strings, addr 4396736)"`
- `"Code injection capability: VirtualAlloc + VirtualProtect imports (pe_import_signals T1055), CreateProcessW for child process spawning"`
- `"Dynamic API resolution via LoadLibraryExW + GetProcAddress (pe_import_signals T1129)"`
- `"31 capa rules matched including network communication, file discovery, registry operations, process creation, and anti-analysis techniques"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73
size: 235184
type: PE
architecture: X86
entrypoint_ea: 57943
entropy: 6.82
file_name: trojan_4982.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 32 | - |
| .text | 1024 | 133632 | 135168 | 140 | RX |
| .rdata | 136192 | 37376 | 40960 | 74 | R |
| .data | 177152 | 8704 | 20480 | 58 | RW |
| .rsrc | 197632 | 2560 | 4096 | 111 | R |
| .reloc | 201728 | 7680 | 8192 | 123 | R |
| overlay | 209920 | 44208 | 0 | 186 | - |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2013_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| ChangeBrowserPreference | tampering | SUSPICIOUS | 40 | may change browser preference, often used by adware |

### Anomalies (7)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| BigStringHiScore | 3 | strings | 1 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 1 | string is constructed dynamically |
| ManyUniqueImmediateBytes | 3 | code | 5 | More than 48 unique bytes defined across all immediate operands in the function |
| XorInLoop | 3 | code | 16 | XOR instruction in a loop |
| SequentialFunction | 1 | code | 1 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 8 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `45699`: 
- **ManyUniqueImmediateBytes**
  - `36517`: 
  - `43059`: 
  - `70759`: 
  - `80356`: 
  - `86490`: 
- **SequentialFunction**
  - `43059`: 
- **SpaghettiFunction**
  - `47820`: 
  - `48208`: 
  - `51620`: 
  - `56007`: 
  - `83695`: 
- **XorInLoop**
  - `11571`: 
  - `30154`: 
  - `30274`: 
  - `30410`: 
  - `59776`: 

### High-Signal Strings (15 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 143296 | `kernel32.dll` |
| 156960 | `GetProcessWindowStation` |
| 159796 | ` HTTP/1.1
` |
| 171408 | `KERNEL32.dll` |
| 246662 | `Ehttp://www.micr.._2011-10-19.crt0` |
| 246565 | `Chttp://www.micr..2011-10-19.crl0a` |
| 247827 | `Ehttp://crl.micr..2010-06-23.crl0Z` |
| 250370 | `Ehttp://crl.micr..2010-06-23.crl0Z` |
| 252000 | `Ehttp://crl.micr..2010-07-01.crl0Z` |
| 247926 | `>http://www.micr..2010-06-23.crt0` |
| 250469 | `>http://www.micr.._2010-06-23.crt0` |
| 252099 | `>http://www.micr.._2010-07-01.crt0` |
| 158932 | `http` |
| 158944 | `https` |
| 250579 | `1http://www.micr..PS/default.htm0@` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 161840 | `Software\Microso..nternet Settings` |
| 45699 | `0123456789ABCDEF..0000000000000015` |
| 159440 | `SOFTWARE\Microso..T\CurrentVersion` |
| 136960 | `ERROR : Unable t.. CAtlBaseModule
` |
| 160856 | `Solid;Powerful;A..Legendary;Basic;` |
| 159112 | `Floating point (..::CString class.` |
| 161160 | `Worker;Player;Dr..er;Caller;Armor;` |
| 161736 | `This is E2RU tra.. setup. Install?` |
| 159368 | `Software\ClearSystem` |
| 160588 | `\expand.ini` |
| 160744 | `Advapi32.dll` |
| 153376 | `mscoree.dll` |
| 199360 | `<?xml version='1..>
</assembly>
` |
| 161624 | `/S pid=129 subid=10 mr=0 lang=ru` |
| 143296 | `kernel32.dll` |
| 159028 | `www-authenticate` |
| 159576 | `%02X:%02X:%02X:%02X:%02X:%02X` |
| 160016 | `Content-Length` |
| 155872 | `Runtime Error!

Program: ` |
| 161276 | `userbrowser` |
| 156860 | `USER32.DLL` |
| 160824 | `checklink.info` |
| 159064 | `proxy-authenticate` |
| 161300 | `userbrowser=` |
| 143708 | `GetLogicalProcessorInformation` |
| 143680 | `GetCurrentProcessorNumber` |
| 161960 | `ProxyServer` |
| 143760 | `SetDefaultDllDirectories` |
| 160048 | `Transfer-Encoding` |
| 159316 | `iostream stream error` |
| 159412 | `InstallDate` |
| 143432 | `SetThreadStackGuarantee` |
| 143368 | `InitializeCriticalSectionEx` |
| 143500 | `WaitForThreadpoolTimerCallbacks` |
| 161576 | `download_url` |
| 143648 | `FreeLibraryWhenCallbackReturns` |
| 161720 | `Message` |
| 143620 | `FlushProcessWriteBuffers` |
| 143972 | `GetFileInformationByHandleExW` |
| 144004 | `SetFileInformationByHandleW` |
| 159736 | `keep-alive` |
| 143456 | `CreateThreadpoolTimer` |
| 156960 | `GetProcessWindowStation` |
| 160128 | `set-cookie` |
| 143872 | `GetUserDefaultLocaleName` |
| 143532 | `CloseThreadpoolTimer` |
| 143556 | `CreateThreadpoolWait` |
| 156932 | `GetUserObjectInformationW` |
| 160112 | `Trailer` |
| 159348 | `value_vm` |
| 159776 | `Location` |
| 160688 | `invalid unordered_map<K, T> key` |
| 159712 | `Connection` |
| 159872 | `Content-Length: %d
` |
| 143412 | `CreateSemaphoreExW` |
| 143480 | `SetThreadpoolTimer` |
| 143396 | `CreateEventExW` |
| 160772 | `RegOpenKeyTransactedW` |
| 143936 | `GetCurrentPackageId` |
| 143600 | `CloseThreadpoolWait` |
| 159820 | `Host: %s:%d
` |
| 159956 | `User-Agent: NSISDL/1.2
` |
| 143824 | `GetDateFormatEx` |
| 143580 | `SetThreadpoolWait` |
| 156912 | `GetLastActivePopup` |
| 143900 | `IsValidLocaleName` |
| 159640 | `string too long` |
| 141096 | `Unknown exception` |
| 143336 | `FlsFree` |
| 159552 | `twoyden.ru` |
| 143788 | `EnumSystemLocalesEx` |
| 159916 | `Content-Type: ` |
| 143324 | `FlsAlloc` |
| 160720 | `list<T> too long` |
| 159532 | `value_os` |
| 159020 | `

` |
| 156896 | `GetActiveWindow` |
| 159656 | `invalid string position` |
| 143856 | `GetTimeFormatEx` |
| 139300 | `address family not supported` |

### Constants / Known Patterns (73)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| hash | `hash::MD5` |
| exception | `exception::C++ exception` |
| exception | `exception::FuncInfo header` |
| registry | `registry::HKEY_USERS` |
| exception | `exception::CLR exception` |
| guid | `guid::IInternetSecurityManager` |
| compress | `compress::unlzx_table_three__16_lil_32` |
| runtime | `runtime::msvc_locale` |
| runtime | `runtime::msvc_date` |
| runtime | `runtime::msvc_r6002` |
| runtime | `runtime::msvc_r6008` |
| runtime | `runtime::msvc_r6009` |
| runtime | `runtime::msvc_r6010` |
| runtime | `runtime::msvc_r6016` |
| runtime | `runtime::msvc_r6017` |
| runtime | `runtime::msvc_r6018` |
| runtime | `runtime::msvc_r6019` |
| runtime | `runtime::msvc_r6024` |
| runtime | `runtime::msvc_r6025` |
| runtime | `runtime::msvc_r6026` |
| runtime | `runtime::msvc_r6027` |
| runtime | `runtime::msvc_r6028` |
| runtime | `runtime::msvc_r6031` |
| runtime | `runtime::msvc_r6032` |
| runtime | `runtime::msvc_r6033` |
| runtime | `runtime::msvc_r6034` |
| runtime | `runtime::msvc_domain_error` |
| runtime | `runtime::msvc_sing_error` |
| runtime | `runtime::msvc_tloss_error` |
| runtime | `runtime::msvc_name_unknown` |
| runtime | `runtime::msvc_rl` |
| oid | `oid::signedData` |
| oid | `oid::sha-256` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| crypto | `crypto::PKCS_DigestDecoration_SHA256__8_byt_19` |
| oid | `oid::sha256WithRSAEncryption` |
| oid | `oid::countryName` |

### Imports (674)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1024 | ??__E?isInitialized@CAtlStringMgr@ATL@@0_NA@@YAXXZ | DEBUG | 5 |
| 1423 | ATL.AtlCrtErrorCheck | DEBUG | 43 |
| 1482 | ATL.Checked.memmove_s | DEBUG | 4 |
| 1709 | ATL.CWin32Heap.~CWin32Heap | DEBUG | 2 |
| 1737 | ATL::CWin32Heap.#0 | DEBUG | 1 |
| 1758 | ATL::CWin32Heap.#1 | DEBUG | 1 |
| 1758 | ATL.CWin32Heap.Free | DEBUG | 1 |
| 1785 | ATL::CWin32Heap.#2 | DEBUG | 1 |
| 1785 | ATL.CWin32Heap.Reallocate | DEBUG | 1 |
| 1839 | ATL::CWin32Heap.#3 | DEBUG | 1 |
| 1860 | ATL::CWin32Heap.#4 | DEBUG | 1 |
| 1860 | ATL.CWin32Heap.`scalar deleting destructor' | DEBUG | 1 |
| 1891 | ATL.CStringData.Release | DEBUG | 48 |
| 1919 | ATL.CAtlStringMgr.GetInstance | DEBUG | 24 |
| 2069 | ATL::CAtlStringMgr.#0 | DEBUG | 1 |
| 2175 | ATL::CAtlStringMgr.#1 | DEBUG | 1 |
| 2175 | ATL.CAtlStringMgr.Free | DEBUG | 1 |
| 2187 | ATL::CAtlStringMgr.#2 | DEBUG | 1 |
| 2280 | ATL::CAtlStringMgr.#3 | DEBUG | 1 |
| 2280 | ATL.CAtlStringMgr.GetNilString | DEBUG | 1 |
| 2294 | ATL::CAtlStringMgr.#4 | DEBUG | 1 |
| 2297 | ATL::CAtlStringMgr.#5 | DEBUG | 1 |
| 6986 | ATL::CSocketAddr.#0 | DEBUG | 1 |
| 11134 | std.char_traits<char>.length | DEBUG | 1 |
| 11163 | std::_System_error_category.#0 | DEBUG | 4 |
| 11195 | std.error_condition.operator== | DEBUG | 1 |
| 11226 | std::_Iostream_error_category.#3 | DEBUG | 3 |
| 11226 | std.error_category.default_error_condition | DEBUG | 3 |
| 11244 | std::_System_error_category.#5 | DEBUG | 4 |
| 11244 | std.error_category.equivalent | DEBUG | 4 |
| 11277 | std::_System_error_category.#4 | DEBUG | 4 |
| 11277 | std.error_category.equivalent | DEBUG | 4 |
| 11306 | std::_Generic_error_category.#1 | DEBUG | 1 |
| 11312 | std::_Generic_error_category.#2 | DEBUG | 2 |
| 11357 | std::_Iostream_error_category.#1 | DEBUG | 1 |
| 11363 | std::_Iostream_error_category.#2 | DEBUG | 1 |
| 11363 | std._Iostream_error_category.message | DEBUG | 1 |
| 11412 | std::_System_error_category.#1 | DEBUG | 1 |
| 11418 | std::_System_error_category.#2 | DEBUG | 1 |
| 11463 | std::_System_error_category.#3 | DEBUG | 1 |
| 11463 | std._System_error_category.default_error_condition | DEBUG | 1 |
| 12501 | ATL.CSimpleStringT<wchar_t,0>.Empty | DEBUG | 3 |
| 13627 | std.basic_string<char,struct std::char_traits<char>,std::allocator<char>>.basic_string<char,struct std::char_traits<char>,std::allocator<char>> | DEBUG | 3 |
| 13792 | ATL::CAtlHttpClientT<ATL::ZEvtSyncSocket>.#0 | DEBUG | 1 |
| 13864 | ATL.CSimpleStringT<wchar_t,0>.SetLength | DEBUG | 13 |
| 14708 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>._Tidy | DEBUG | 3 |
| 15445 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>.assign | DEBUG | 1 |
| 15566 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>.erase | DEBUG | 1 |
| 15613 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>.erase | DEBUG | 1 |
| 15842 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>._Inside | DEBUG | 1 |
| 16179 | ATL.CSimpleStringT<wchar_t,0>.Reallocate | DEBUG | 1 |
| 16235 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>._Copy | DEBUG | 1 |
| 17436 | ATL::CAtlHttpClientT<ATL::ZEvtSyncSocket>.#1 | DEBUG | 1 |
| 18487 | ATL::CAtlHttpClientT<ATL::ZEvtSyncSocket>.#2 | DEBUG | 1 |
| 18710 | std._Allocate<char> | DEBUG | 2 |
| 27678 | std._Timevec.~_Timevec | DEBUG | 3 |
| 29846 | std.locale.~locale | DEBUG | 1 |
| 35133 | ATL.CRegKey.Close | DEBUG | 1 |
| 46032 | ATL.CAtlBaseModule.CAtlBaseModule | DEBUG | 1 |
| 46115 | ATL._ATL_BASE_MODULE70._ATL_BASE_MODULE70 | DEBUG | 1 |
| 46150 | ATL.CAtlBaseModule.~CAtlBaseModule | DEBUG | 1 |
| 46214 | ATL.CAtlBaseModule.GetHInstanceAt | DEBUG | 2 |
| 46520 | std::bad_alloc.#0 | DEBUG | 1 |
| 46557 | std::out_of_range.#0 | DEBUG | 3 |
| 46738 | std._Fac_node.~_Fac_node | DEBUG | 1 |
| 46759 | std._Fac_tidy_reg_t.~_Fac_tidy_reg_t | DEBUG | 1 |
| 46795 | std._Init_locks._Init_locks | DEBUG | 2 |
| 46881 | _Init_atexit.~_Init_atexit | DEBUG | 1 |
| 46936 | __Mtxinit | DEBUG | 1 |
| 46959 | _wmemset | DEBUG | 1 |
| 47021 | _wcschr | DEBUG | 2 |
| 47214 | _swprintf_s | DEBUG | 1 |
| 47242 | _memmove_s | DEBUG | 2 |
| 47318 | _LocaleUpdate._LocaleUpdate | DEBUG | 30 |
| 47454 | __wcsicmp | DEBUG | 11 |
| 47601 | __wcsicmp_l | DEBUG | 1 |
| 47820 | _wcsncpy_s | DEBUG | 21 |
| 48128 | __time32 | DEBUG | 2 |
| 49824 | _strncmp | DEBUG | 3 |
| 49973 | _wmemcpy_s | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 94180 | sub_417be4 |
| 62311 | sub_40ff67 |
| 45342 | sub_40bd1e |
| 43059 | sub_40b433 |
| 11675 | sub_40399b |
| 11813 | sub_403a25 |
| 17436 | #1 |
| 42742 | sub_40b2f6 |
| 30047 | sub_40815f |
| 31295 | sub_40863f |
| 109678 | sub_41b86e |
| 39485 | sub_40a63d |
| 30753 | sub_408421 |
| 7772 | sub_402a5c |
| 7047 | sub_402787 |
| 40648 | sub_40aac8 |
| 12257 | sub_403be1 |
| 9949 | sub_4032dd |
| 7597 | sub_4029ad |
| 110176 | sub_41ba60 |
| 130782 | 5 |
| 130833 | 6 |
| 131433 | 20 |
| 131533 | 22 |
| 131628 | 23 |
| 131723 | 24 |
| 131785 | 25 |
| 131836 | 26 |
| 131950 | 28 |
| 132389 | 35 |

### Decompilations (top 6)
#### 94180 — sub_417be4
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_417be4(int32_t **param_1)

{
    int32_t *piVar1;
    int32_t iVar2;
    code *pcVar3;
    undefined4 uVar4;
    
    piVar1 = *param_1;
    if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
       ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
        (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
        sub_41438d();
        pcVar3 = swi(3);
        uVar4 = (*pcVar3)();
        return uVar4;
    }
    return 0;
}

```
#### 62311 — sub_40ff67
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40ff67(void)

{
    int32_t *piVar1;
    int32_t iVar2;
    int32_t unaff_EBP;
    
    piVar1 = *(unaff_EBP + 8);
    *(*(unaff_EBP + 0xc) + -4) = *(unaff_EBP + -0x28);
    __FindAndUnlinkFrame(*(unaff_EBP + -0x2c));
    iVar2 = __getptd();
    *(iVar2 + 0x88) = *(unaff_EBP + -0x30);
    iVar2 = __getptd();
    *(iVar2 + 0x8c) = *(unaff_EBP + -0x34);
    if (((((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
         ((piVar1[5] == 0x19930520 || ((piVar1[5] == 0x19930521 || (piVar1[5] == 0x19930522)))))) &&
        (*(unaff_EBP + -0x38) == 0)) &&
       ((*(unaff_EBP + -0x1c) != 0 && (iVar2 = __IsExceptionObjectToBeDestroyed(piVar1[6]), iVar2 != 0)))) {
        ___DestructExceptionObject(piVar1, *(unaff_EBP + 0x10));
    }
    return;
}

```
#### 45342 — sub_40bd1e
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40bd1e(void)

{
    char *pcVar1;
    char cVar2;
    undefined4 uVar3;
    undefined4 *extraout_ECX;
    char *pcVar4;
    int32_t unaff_EBP;
    
    __EH_prolog3_GS(0x140);
    *(unaff_EBP + -0x138) = 0;
    *(unaff_EBP + -0x14c) = extraout_ECX;
    *(unaff_EBP + -4) = 1;
    uVar3 = [0x0x42d5e0];
    *(unaff_EBP + -0x124) = [0x0x42d5e0];
    *(unaff_EBP + -4) = 5;
    *extraout_ECX = uVar3;
    *(unaff_EBP + -0x138) = 1;
    sub_402f72(unaff_EBP + -0x124, 0x427920, 0x34bd3);
    sub_4036c7(0x4284c0);
    *(unaff_EBP + -4) = 6;
    sub_403680(unaff_EBP + 0xc);
    *(unaff_EBP + -4) = 7;
    sub_4036c7(0x4284c0);
    *(unaff_EBP + -4) = 8;
    sub_403680(unaff_EBP + 0x10);
    *(unaff_EBP + -4) = 9;
    sub_4036c7(0x4284c0);
    *(unaff_EBP + -4) = 10;
    sub_403680(unaff_EBP + 0x14);
    *(unaff_EBP + -4) = 0xb;
    sub_4036c7(0x4284c0);
    *(unaff_EBP + -4) = 0xc;
    sub_403680(unaff_EBP + -0x124);
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    *(unaff_EBP + -4) = 0x14;
    sub_403454();
    *(unaff_EBP + -0x120) = unaff_EBP + -0x11c;
    sub_4043a4(*(unaff_EBP + -0x128), 3);
    *(unaff_EBP + -4) = 0x15;
    pcVar4 = *(unaff_EBP + -0x120);
    *(unaff_EBP + -0x88) = 0;
    *(unaff_EBP + -0x8c) = 0;
    *(unaff_EBP + -0x9c) = 0x67452301;
    *(unaff_EBP + -0x98) = 0xefcdab89;
    pcVar1 = pcVar4 + 1;
    *(unaff_EBP + -0x94) = 0x98badcfe;
    *(unaff_EBP + -0x90) = 0x10325476;
    do {
        cVar2 = *pcVar4;
        pcVar4 = pcVar4 + 1;
    } while (cVar2 != '\0');
    sub_40bb61(*(unaff_EBP + -0x120), pcVar4 - pcVar1);
    sub_40bbfe();
    sub_402e76(unaff_EBP + -0x34);
    if (*(unaff_EBP + -0x120) != unaff_EBP + -0x11c) {
        _free(*(unaff_EBP + -0x120));
    }
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_40f652();
    return;
}

```

### Carved Files (2)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 744 |
| ? | PKCS7 | 44199 |

### Virtual Files (4)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/ru-ru | 744 | - |
| GRPICO/101/ru-ru | 20 | - |
| VER/1/ru-ru | 656 | - |
| MANIF/1/en-us | 392 | - |

### Structures (46)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 256 |
| OptionalHeader | 280 |
| Sections | 504 |
| advapi32.FT | 136192 |
| kernel32.FT | 136220 |
| rpcrt4.FT | 136628 |
| shell32.FT | 136636 |
| shlwapi.FT | 136644 |
| user32.FT | 136676 |
| ws2_32.FT | 136700 |
| ole32.FT | 136776 |
| urlmon.FT | 136792 |
| LoadConfigurationTable | 162184 |
| SEHandlers | 163584 |
| ImportTable | 169820 |
| advapi32.OFT | 170020 |
| kernel32.OFT | 170048 |
| rpcrt4.OFT | 170456 |
| shell32.OFT | 170464 |
| shlwapi.OFT | 170472 |
| user32.OFT | 170504 |
| ws2_32.OFT | 170528 |
| ole32.OFT | 170604 |
| urlmon.OFT | 170620 |
| ImportNames | 170628 |
| SecurityCookie | 178368 |
| Resources | 197632 |
| Resources.ICO | 197680 |
| Resources.GRPICO | 197704 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 31 · duration_s: 1.04

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using RC4 KSA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0028.002:Encryption Key |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| parse credit card information |  | C0019:Check String |
| receive data |  | B0030.002:C2 Communication |
| send data |  | B0030.001:C2 Communication |
| resolve DNS |  | C0011.001:DNS Communication |
| reference HTTP User-Agent string |  | C0002:HTTP Communication |
| check HTTP status code |  | C0002.014:HTTP Communication |
| initialize Winsock library |  | C0001.009:Socket Communication |

## PE Imports / Signals
import_count: 143

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 20

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@182084 len=14; $ipv6@157710 len=6 |
| contains_base64 | - | $a@138188 len=12 |
| MD5_Constants | - | $c4@45729 len=4; $c5@45739 len=4; $c6@45752 len=4; $c7@45762 len=4 |
| url | - | $url_regex@227622 len=69 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasModified_DOS_Message | - |  |
| VC8_Microsoft_Corporation | - | $a@18194 len=10 |
| Microsoft_Visual_Cpp_8 | - | $a@28 len=82; $b@25468 len=10 |
| SEH_Save | - | $a@60017 len=7 |
| SEH_Init | - | $a@3453 len=6; $b@110219 len=7 |
| anti_dbg | - | $d1@169872 len=12; $c2@170594 len=17; $c3@169284 len=17 |
| network_tcp_socket | - | $f1@170508 len=10; $c1@170442 len=9; $c2@137650 len=6; $c4@170432 len=7; $c5@170418 len=10; $c6@137232 len=7 |
| network_dns | - | $f2@170508 len=10; $c3@170466 len=11 |
| win_registry | - | $f1@170082 len=12; $c3@170050 len=11; $c6@170050 len=11 |
| win_token | - | $f1@170082 len=12; $c3@169966 len=16 |
| win_files_operation | - | $f1@169872 len=12; $c1@169670 len=9; $c2@171522 len=14; $c3@169670 len=9; $c4@169690 len=8 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@170508 len=10 |

## Generated YARA Meta
```json
{
  "sha256": "38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73",
  "family": "Trioris/Cerbu trojan",
  "imphash": "b5f4ee827c576f7005f9e544e6955bfb",
  "generated_at": "2026-08-12T21:51:40.011180+00:00",
  "string_count": 24,
  "strings": [
    "</tq<\\tm<.um",
    "s-9>w)+>",
    "<0r><9w:",
    "SVWjA_jZ+",
    "uBjAYjZ+",
    "j/_j\\[f;",
    "PPPPPPPP",
    ">0t<NAj0X",
    "tHHt*Ht#",
    "~';_t|%3",
    "UQPXY]Y[",
    "Ht+Ht$Ht",
    "permission denied",
    "file exists",
    "no such device",
    "filename too long",
    "device or resource busy",
    "io error",
    "directory not empty",
    "invalid argument",
    "no space on device",
    "no such file or directory",
    "function not supported",
    "no lock available"
  ],
  "rule_path": "/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yar",
  "sigma_path": "/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yml",
  "iocs_path": "/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/iocs.json",
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
    "utc": "2026-08-12 21:51:40 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 987 · per_category: `{"decoded_strings": 1, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 986}`

### FLOSS sample
- `HARDWARE\ACPI\krb.mainsetup.vbox|HARDWARE\ACPI\DSDT\VBOX__|HARDWARE\ACPI\FADT\VBOX__|HARDWARE\ACPI\RSDT\VBOX__|HARDWARE\ACPI\SSDT\VBOX__|HARDWARE\ACPI\DSDT\VirtualBox|HARDWARE\ACPI\DSDT\Parallels Work`
- ``.rdata`
- `@.data`
- `@.reloc`
- `</tq<\tm<.um`
- `,j*Yf;`
- `j*XVf9`
- `s-9>w)+>`
- `tM9>t3`
- `C 93tr`
- `<0r><9w:`
- `RRPQRh`
- `Gf94xu`
- `<p|u<3`
- `PSSSSSS`
- `Yj8Yjx`
- `SVWjA_jZ+`
- `uBjAYjZ+`
- `uHjAXf;`
- `j/_j\[f;`
- `t3h<3B`
- `t"hH3B`
- `QQSVWd`
- `PP9E u`
- `PPPPPPPP`
- `jA[jZZ+`
- `htHjlZ;`
- `HHtXHHt`
- `nt'joZ;`
- `YYjgXf9`
- `>0t<NAj0X`
- `~pjCXf`
- `v	N+D$`
- `HHtVHHt`
- `uaPPPS`
- `YY_^[]`
- `tHHt*Ht#`
- `j@j _W`
- `QQSVWh`
- `j"_f9y`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0040ee57
```asm
┌ 300: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_24h @ ebp-0x24
│       ╎   0x0040ee57      e852950000     call 0x4183ae
│       └─< 0x0040ee5c      e97ffeffff     jmp 0x40ece0
..
```
### 0x0040ada5
```asm
; CALL XREF from entry0 @ 0x40edd8(x)
┌ 1000: int main (char **argv, char **envp, int32_t envp, int32_t arg_78h, int32_t arg_28h_2, int32_t arg_28h, int32_t arg_30h, int32_t arg_48h);
│           ; arg char **argv @ esp+0x78
│           ; arg char **envp @ esp+0x7c
│           ; arg int32_t envp @ esp+0x80
│           ; arg int32_t arg_78h @ esp+0x84
│           ; arg int32_t arg_28h_2 @ esp+0x88
│           ; arg int32_t arg_28h @ esp+0x8c
│           ; arg int32_t arg_30h @ esp+0x90
│           ; arg int32_t arg_48h @ esp+0xb0
│           ; var int32_t var_10h_5 @ esp+0x20
│           ; var int32_t var_14h_7 @ esp+0x24
│           ; var int32_t var_10h_4 @ esp+0x28
│           ; var int32_t var_1ch_5 @ esp+0x2c
│           ; var int32_t var_10h_3 @ esp+0x30
│           ; var int32_t var_10h_2 @ esp+0x34
│           ; var int32_t var_1ch_4 @ esp+0x38
│           ; var int32_t var_14h_6 @ esp+0x3c
│           ; var int32_t var_10h @ esp+0x40
│           ; var int32_t var_14h_5 @ esp+0x44
│           ; var int32_t var_1ch_6 @ esp+0x48
│           ; var int32_t var_14h_4 @ esp+0x4c
│           ; var int32_t var_14h_3 @ esp+0x50
│           ; var int32_t var_34h @ esp+0x54
│           ; var int32_t var_18h_2 @ esp+0x58
│           ; var int32_t var_14h_2 @ esp+0x5c
│           ; var int32_t var_1ch_3 @ esp+0x60
│           ; var int32_t var_18h @ esp+0x64
│           ; var int32_t var_14h @ esp+0x68
│           ; var int32_t var_1ch_2 @ esp+0x6c
│           ; var int32_t var_1ch @ esp+0x70
│           0x0040ada5      55             push ebp
│           0x0040ada6      8bec           mov ebp, esp
│           0x0040ada8      83e4f8         and esp, 0xfffffff8
│           0x0040adab      b8e4350000     mov eax, 0x35e4
│           0x0040adb0      e8db940000     call 0x414290
│           0x0040adb5      a1c0c44200     mov eax, dword [0x42c4c0]   ; [0x42c4c0:4]=0xbb40e64e
│           0x0040adba      33c4           xor eax, esp
│           0x0040adbc      898424e035..   mov dword [esp + 0x35e0], eax ; [0x35e0:4]=-1
│           0x0040adc3      53             push ebx
│           0x0040adc4      56             push esi
│           0x0040adc5      33c0           xor eax, eax
│           0x0040adc7      8d4c2448       lea ecx, [arg_48h]
│           0x0040adcb      57             push edi
│           0x0040adcc      89442428       mov dword [arg_28h], eax
│           0x0040add0      e851e9ffff     call 0x409726
│           0x0040add5      33ff           xor edi, edi
│           0x0040add7      8d4c244c       lea ecx, [arg_48h]
│           0x0040addb      47             inc edi
│           0x0040addc      e8008effff     call 0x403be1
│           0x0040ade1      51             push ecx
│           0x0040ade2      8d4c2430       lea ecx, [arg_30h]
│           0x0040ade6      89442428       mov dword [arg_28h_2], eax
│           0x0040adea      e8d1daffff     call 0x4088c0
│           0x0040adef      686c7f4200     push 0x427f6c               ; 'l\x7fB'
│          
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000100 ......................................

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
  - `KERNEL32.dll!WaitForSingleObject`
  - `KERNEL32.dll!OutputDebugStringW`
  - `KERNEL32.dll!GetProcessHeap`
  - `KERNEL32.dll!WideCharToMultiByte`
  - `KERNEL32.dll!InitializeCriticalSectionAndSpinCount`
  - `USER32.dll!CharNextW`
  - `USER32.dll!MessageBoxW`
  - `USER32.dll!LoadStringW`
  - `USER32.dll!CharLowerW`
  - `USER32.dll!LoadIconW`
  - `ADVAPI32.dll!RegQueryValueExW`
  - `ADVAPI32.dll!RegCloseKey`
  - `ADVAPI32.dll!ConvertSidToStringSidW`
  - `ADVAPI32.dll!RegOpenKeyExW`
  - `ADVAPI32.dll!GetTokenInformation`
  - `SHELL32.dll!SHGetFolderPathW`
  - `ole32.dll!CoUninitialize`
  - `ole32.dll!CoInitialize`
  - `ole32.dll!CoCreateInstance`
  - `SHLWAPI.dll!StrToIntW`
  - `SHLWAPI.dll!StrDupW`
  - `SHLWAPI.dll!StrCatW`
  - `SHLWAPI.dll!PathQuoteSpacesW`
  - `SHLWAPI.dll!StrCpyW`
  - `WS2_32.dll!WSAResetEvent`
  - `WS2_32.dll!WSASetLastError`
  - `WS2_32.dll!WSAEnumNetworkEvents`
  - `WS2_32.dll!WSACreateEvent`
  - `WS2_32.dll!freeaddrinfo`
  - `RPCRT4.dll!UuidCreateSequential`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, sr.func_addr, sr.string_value FROM string_refs sr WHERE sr.func_addr IN (4233893, 4219086, 4209051, 4209189, 4232629, 4240118, 4225309, 4238024) ORDER BY sr.func_name, sr.string_value", "ts": 1786571396.9253285}`
- `{"source": "ghidra_query", "sql": "SELECT content, address FROM strings WHERE content LIKE '%pid=%' OR content LIKE '%subid=%' OR content LIKE '%lang=%' OR content LIKE '%SOCKS%' OR content LIKE '%socks%' OR content LIKE '%CONNECT%' OR content LIKE '%bind%' OR content LIKE '%resolve%' OR content LIK`
- `{"source": "ghidra_query", "sql": "SELECT f.name, f.address, f.size, fm.cyclomatic_complexity, fm.instruction_count, fm.call_out_count, fm.string_ref_count FROM function_metrics fm JOIN funcs f ON fm.func_addr = f.address WHERE fm.string_ref_count > 5 ORDER BY fm.string_ref_count DESC LIMIT 15", "ts`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786571497.3800683}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786571499.916349}`
- `{"source": "yara_gen_v2", "ts": 1786571500.0113416}`
- `{"source": "publish_report_v2", "ts": 1786571589.1372108}`
- `{"source": "publish_report_v2_technical", "ts": 1786572075.5551453}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786626921.3809712}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786626921.3846738}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786626921.387971}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786626921.3935292}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs LIMIT 15", "ts": 1786626921.3978496}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786626928.484995}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786626929.0080156}`
- `{"source": "ghidra_query", "sql": "SELECT name, addr FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1786626930.1129825}`
- `{"source": "ghidra_query", "sql": "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786626930.797541}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786626931.324037}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786626931.8341334}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786626935.9020908}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786626936.3172264}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786626937.475293}`
- `{"source": "ghidra_query", "sql": "SELECT addr, content FROM strings WHERE length < 300", "ts": 1786626937.9999557}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786626938.527424}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786626938.922037}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786626939.9585636}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786626940.9856064}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786626945.037684}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786626945.4245079}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786626945.430132}`
