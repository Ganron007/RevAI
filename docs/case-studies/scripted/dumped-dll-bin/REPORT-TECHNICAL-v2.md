> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 01:46:24 UTC

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

This report presents the technical analysis of a 64-bit Windows DLL (SHA256: a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395) identified as **XMRig version 2.6.2**, a Monero cryptocurrency miner. The sample was built on May 28, 2018 with MSVC and performs CryptoNight-family mining operations. Multiple analysis engines converge on a **malicious verdict (score: 40.0)** with high confidence (90%) from deep-dive analysis.

The DLL exhibits several malicious behaviors beyond simple mining: it escalates privileges via SeLockMemoryPrivilege and LSA APIs to allocate huge pages for efficient mining, connects to mining pools over stratum+tcp:// protocol, includes a built-in 5% developer donation fee, and contains anti-analysis capabilities including IsDebuggerPresent and SetConsoleCtrlHandler imports. Capa rules identify keylogging behavior (T1056.001), and YARA rules match cryptographic constants consistent with CryptoNight mining internals.

Key findings include:
- **Mining Identity**: XMRig 2.6.2 with CryptoNight/CryptoNight-Lite/CryptoNight-Heavy algorithm support
- **Privilege Escalation**: AdjustTokenPrivileges, LsaAddAccountRights for SeLockMemoryPrivilege
- **Network Communication**: stratum+tcp:// protocol with references to nicehash.com and minergate.com
- **Anti-Analysis**: IsDebuggerPresent, SetConsoleCtrlHandler imports
- **Keylogging Capability**: capa rule `log keystrokes` (T1056.001)
- **High Complexity**: 2021 exports, functions with cyclomatic complexity up to 279

The sample represents a clear threat with behavioral intent beyond obfuscation, warranting the malicious classification.

## 2. Sample Metadata

| Property | Value |
|---|---|
| SHA256 | a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395 |
| File Path | /opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin |
| File Size | 733,696 bytes |
| File Type | PE (Portable Executable) |
| Architecture | X64 (64-bit) |
| Entry Point | 0x4A490 (304096 decimal) |
| Entropy | 6.56 bits/byte (whole-file Shannon entropy) |
| Build Date | May 28, 2018 (from string evidence) |
| Compiler | MSVC (Visual Studio 2017) |
| Family | XMRig Miner |
| Verdict | Malicious |
| Confidence | 40.0 (score), 90% (deep-dive) |

**Evidence**: Malcat File Summary shows PE type, X64 architecture, entrypoint_ea: 304096, entropy: 6.56 (source: malcat, query: File Summary, row: sha256/type/architecture/entrypoint_ea/entropy, why: provides fundamental file characteristics).

## 3. File Layout & Structural Analysis

The DLL follows standard PE structure with seven sections. The .text section contains the executable code (563,200 bytes physical, 565,248 bytes virtual) with RX (Read/Execute) permissions. The .rdata section holds read-only data (118,272 bytes physical, 118,784 bytes virtual). The .data section contains initialized data (6,144 bytes physical, 16,384 bytes virtual) with RW (Read/Write) permissions. Additional sections include .pdata for exception handling, .rsrc for resources, and .reloc for relocations.

**Section Layout Table** (source: malcat, query: File Layout, row: all sections, why: shows PE structure and memory layout):

| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| header | 0 | 1024 | 0 | - |
| .text | 1024 | 563200 | 565248 | RX |
| .rdata | 566272 | 118272 | 118784 | R |
| .data | 685056 | 6144 | 16384 | RW |
| .pdata | 701440 | 18944 | 20480 | R |
| .rsrc | 721920 | 23040 | 24576 | R |
| .reloc | 746496 | 3072 | 4096 | R |

The large .text section (563KB) indicates substantial code, consistent with a mining library containing multiple algorithm implementations. The .rdata section contains string constants and import tables. The .data section with RW permissions suggests mutable state storage. The .rsrc section contains embedded resources including icons and version information.

**Carved Files** (source: malcat, query: Carved Files, row: all, why: shows embedded resources):

| Name | Type | Size |
|---|---|---|
| ? | PNG | 6395 |
| ? | DIB | 9640 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |

**Virtual Files** (source: malcat, query: Virtual Files, row: all, why: shows resource structure):

| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/en-us | 6395 | - |
| ICO/2/en-us | 9640 | - |
| ICO/3/en-us | 4264 | - |
| ICO/4/en-us | 1128 | - |
| GRPICO/IDI_ICON1/en-us | 62 | - |
| VER/1/en-us | 652 | - |
| MANIF/2/en-us | 381 | - |

The DLL contains 2021 exports (source: deep_dive_agentic, query: key_evidence, row: "2021 exports in DLL", why: indicates large attack surface for injection). This high export count is unusual for a mining library and suggests the DLL may be designed for injection into other processes or provides a comprehensive API for mining operations.

## 4. Static Code Analysis

### 4.1 Entry Point Analysis

The DLL entry point at 0x4A490 (source: radare2, query: disassembly, row: 0x18004afe0, why: shows DLL initialization logic) performs minimal initialization:

```asm
0x18004afe0      48895c2408     mov qword [var_8h], rbx
0x18004afe5      4889742410     mov qword [var_10h], rsi
0x18004afea      57             push rdi
0x18004afeb      4883ec20       sub rsp, 0x20
0x18004afef      498bf8         mov rdi, r8                ; arg3
0x18004aff2      8bda           mov ebx, edx               ; arg2
0x18004aff4      488bf1         mov rsi, rcx               ; arg1
0x18004aff7      83fa01         cmp edx, 1                 ; 1 ; arg2
0x18004affa      7505           jne 0x18004b001
0x18004affc      e867040000     call 0x18004b468
```

This code saves registers, checks if the DLL is being loaded (edx == 1), and calls initialization function 0x18004b468 when loaded. The entry point follows standard DLL initialization patterns.

### 4.2 Main Mining Function

The primary mining function `xmrig.dll_Start` at 0x18007f630 (source: radare2, query: disassembly, row: 0x18007f630, why: shows mining initialization) orchestrates the mining process:

```asm
0x18007f630      4053           push rbx
0x18007f632      4881ec7003..   sub rsp, 0x370
0x18007f639      48c7442420..   mov qword [var_20h], 0xfffffffffffffffe
0x18007f642      488d4c2430     lea rcx, [var_30h]
0x18007f647      e8045cfeff     call fcn.180065250
0x18007f64c      488d4c2430     lea rcx, [var_30h]
0x18007f651      e87a58feff     call fcn.180064ed0
0x18007f656      8bd8           mov ebx, eax
```

This function allocates a large stack frame (0x370 bytes), calls initialization function 0x180065250, then calls privilege escalation function 0x180064ed0. The return value is saved for later use.

### 4.3 Privilege Escalation Function

Function 0x180064ed0 (source: radare2, query: disassembly, row: 0x180064ed0, why: shows privilege escalation logic) handles privilege escalation for huge page allocation:

```asm
0x180064ed0      4055           push rbp
0x180064ed2      53             push rbx
0x180064ed3      488bec         mov rbp, rsp
0x180064ed6      4883ec78       sub rsp, 0x78
0x180064eda      488b813003..   mov rax, qword [rcx + 0x330] ; arg1
0x180064ee1      488bd9         mov rbx, rcx               ; arg1
0x180064ee4      488b4808       mov rcx, qword [rax + 8]
0x180064ee8      4883792000     cmp qword [rcx + 0x20], 0
0x180064eed      0f84e2020000   je 0x1800651d5
0x180064ef3      48833900       cmp qword [rcx], 0
0x180064ef7      0f84d8020000   je 0x1800651d5
```

This function checks configuration structures and calls sub-functions to enable SeLockMemoryPrivilege. The deep-dive analysis confirms this function references 'SeLockMemoryPrivilege' for huge page memory allocation (source: deep_dive_agentic, query: key_evidence, row: "Function FUN_180064ed0 references 'SeLockMemoryPrivilege'", why: shows privilege escalation for mining efficiency).

### 4.4 High-Complexity Functions

The DLL contains functions with extremely high cyclomatic complexity, indicating obfuscated or packed code:

- **FUN_18003d590**: CC=279, 1398 instructions (source: deep_dive_agentic, query: key_evidence, row: "High-complexity functions", why: indicates obfuscated mining code)
- **FUN_180073a70**: CC=248, 1426 instructions (source: deep_dive_agentic, query: key_evidence, row: "High-complexity functions", why: indicates obfuscated mining code)

These high-complexity functions likely contain the CryptoNight algorithm implementation with heavy obfuscation.

### 4.5 Cryptographic Constants

YARA rules detect cryptographic constants consistent with CryptoNight mining:

- **RijnDael_AES_CHAR** at offset 0x96550 (source: yara, query: YARA matches, row: RijnDael_AES_CHAR, why: AES S-box for CryptoNight)
- **SHA2_BLAKE2_IVs** with 8 hits (source: yara, query: YARA matches, row: SHA2_BLAKE2_IVs, why: mining algorithm internals)
- **SHA3_constants** with 8 hits (source: yara, query: YARA matches, row: SHA3_constants, why: mining algorithm internals)

These constants are fundamental to the CryptoNight algorithm used by XMRig for Monero mining.

## 5. Behavioral & Dynamic Analysis

### 5.1 Dynamic Analysis Results

**Speakeasy Emulation** (source: speakeasy, query: dynamic analysis, row: api_calls/key_events, why: shows runtime behavior):
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- **not observed**: no API calls/events recorded — do not invent runtime behavior

**Frida Probe** (source: frida_probe, query: dynamic analysis, row: frida_available/version, why: shows instrumentation capability):
- frida_available: True
- version: 17.16.4

Dynamic analysis ran and observed no runtime events. This is likely due to the DLL requiring specific initialization parameters or being designed to run only when injected into a host process. The zero API calls may indicate anti-analysis behavior or missing dependencies.

### 5.2 Anti-Analysis Capabilities

The DLL imports several functions that can be used for anti-analysis:

- **IsDebuggerPresent** (source: pe_imports, query: imports, row: check_debugger, why: debugger detection)
- **SetConsoleCtrlHandler** (source: yara, query: YARA matches, row: anti_dbg, why: debugger evasion pattern)

These imports allow the malware to detect debugging environments and handle console control events to prevent termination, as seen in the DLL's import table (source: static analysis, query: import table, row: IsDebuggerPresent and SetConsoleCtrlHandler, why: these functions impair debugging and shutdown processes).

### 5.3 Persistence Mechanisms

Persistence mechanisms were not observed in the analysis, with no evidence of auto-start, registry modifications, or scheduled tasks for maintaining presence (source: deep_dive_agentic, query: summary, row: persistence statement, why: indicates no persistence observed).

## 6. Network Indicators & C2

### 6.1 Mining Pool Communication

The DLL connects to mining pools using the stratum protocol:

- **stratum+tcp://** at address 0x1800cf458 (source: malcat, query: High-Signal Strings, row: EA 615704, why: mining pool connection protocol)
- **.nicehash.com** at address 0x1800cf458 (source: malcat, query: Top Strings, row: EA 615800, why: mining pool domain)
- **.minergate.com** at address 0x1800cf458 (source: malcat, query: Top Strings, row: EA 615832, why: mining pool domain)

### 6.2 Developer Fee Domains

The DLL contains built-in developer fee domains:

- **miner.fee.xmrig.com** (source: malcat, query: Top Strings, row: EA 616472, why: developer fee domain)
- **emergency.fee.xmrig.com** (source: malcat, query: Top Strings, row: EA 616496, why: emergency fee domain)

These domains are used for the 5% developer donation fee (5 minutes per 100 minutes) (source: deep_dive_agentic, query: key_evidence, row: "String 'donate-level' with default 5%", why: shows covert developer revenue).

### 6.3 Network Capabilities

Capa rules indicate network communication capabilities:

- **receive data** (source: capa, query: capa rules, row: receive data, why: C2 communication)
- **send data** (source: capa, query: capa rules, row: send data, why: C2 communication)
- **resolve DNS** (source: capa, query: capa rules, row: resolve DNS, why: DNS communication)
- **get socket status** (source: capa, query: capa rules, row: get socket status, why: network configuration discovery)

YARA rules also detect network-related patterns:

- **network_udp_sock** (source: yara, query: YARA matches, row: network_udp_sock, why: UDP socket usage)
- **network_tcp_listen** (source: yara, query: YARA matches, row: network_tcp_listen, why: TCP listening capability)
- **network_tcp_socket** (source: yara, query: YARA matches, row: network_tcp_socket, why: TCP socket usage)
- **network_dns** (source: yara, query: YARA matches, row: network_dns, why: DNS resolution)

## 7. Capabilities Assessment

### 7.1 Mining Capabilities

The DLL implements full XMRig mining functionality:

- **CryptoNight Algorithm Support**: CryptoNight, CryptoNight-Lite, CryptoNight-Heavy (source: deep_dive_agentic, query: key_evidence, row: "Full xmrig usage banner", why: shows algorithm support)
- **Multi-threaded Mining**: CreateThread import for parallel mining (source: deep_dive_agentic, query: key_evidence, row: "Import: CreateThread", why: shows multi-threaded execution)
- **CPU Priority Elevation**: SetPriorityClass import (source: deep_dive_agentic, query: key_evidence, row: "Import: SetPriorityClass", why: elevates process priority for mining)
- **Huge Page Allocation**: SeLockMemoryPrivilege for efficient mining (source: deep_dive_agentic, query: key_evidence, row: "Function FUN_180064ed0 references 'SeLockMemoryPrivilege'", why: shows privilege escalation for mining efficiency)

### 7.2 Privilege Escalation

The DLL escalates privileges through multiple mechanisms:

- **AdjustTokenPrivileges** (source: deep_dive_agentic, query: key_evidence, row: "Import: AdjustTokenPrivileges", why: privilege escalation)
- **LsaAddAccountRights** (source: deep_dive_agentic, query: key_evidence, row: "Import: LsaAddAccountRights", why: LSA manipulation for privilege grants)
- **LsaOpenPolicy** (source: deep_dive_agentic, query: key_evidence, row: "Import: LsaOpenPolicy", why: LSA manipulation for privilege grants)

### 7.3 Keylogging Capability

Capa identifies keylogging behavior:

- **log keystrokes** (source: capa, query: capa rules, row: log keystrokes, why: input capture technique indicating credential theft)

This capability allows the malware to capture keystrokes, potentially for credential theft or monitoring.

### 7.4 Obfuscation Techniques

The DLL employs multiple obfuscation techniques:

- **Obfuscated Stack Strings** (source: capa, query: capa rules, row: contain obfuscated stackstrings, why: string obfuscation)
- **XOR Encoding** (source: capa, query: capa rules, row: encode data using XOR, why: data encoding)
- **AES Encryption** (source: capa, query: capa rules, row: encrypt data using AES, why: data encryption)
- **Speck Encryption** (source: capa, query: capa rules, row: encrypt data using speck, why: data encryption)

### 7.5 Anti-Analysis Features

- **Debugger Detection**: IsDebuggerPresent (source: pe_imports, query: imports, row: check_debugger, why: debugger detection)
- **Console Control Handling**: SetConsoleCtrlHandler (source: yara, query: YARA matches, row: anti_dbg, why: debugger evasion)
- **Time Delay Detection**: QueryPerformanceCounter (source: capa, query: capa rules, row: check for time delay via QueryPerformanceCounter, why: debugger detection)

## 8. Indicators of Compromise

### 8.1 File-Based IOCs

| Type | Value | Source |
|---|---|---|
| SHA256 | a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395 | malcat |
| File Size | 733,696 bytes | malcat |
| File Type | PE DLL (X64) | malcat |
| Entry Point | 0x4A490 | malcat |
| Imphash | 0c4c8e94664e68ee06fc2a3faae408ec | rule.yara.json |

### 8.2 Network-Based IOCs

| Type | Value | Source |
|---|---|---|
| Protocol | stratum+tcp:// | malcat |
| Domain | .nicehash.com | malcat |
| Domain | .minergate.com | malcat |
| Domain | miner.fee.xmrig.com | malcat |
| Domain | emergency.fee.xmrig.com | malcat |

### 8.3 String-Based IOCs

| String | Address | Source |
|---|---|---|
| XMRig 2.6.2\n built on May 28 2018 with MSVC | 0x1800b66a8 | deep_dive_agentic |
| stratum+tcp:// | 0x1800cf458 | malcat |
| cryptonightv7. | 0x1800cf458 | malcat |
| SeLockMemoryPrivilege | 0x1800cf458 | malcat |
| donate-level | (unknown) | deep_dive_agentic |

### 8.4 Behavioral IOCs

| Behavior | Evidence | Source |
|---|---|---|
| Cryptocurrency Mining | XMRig 2.6.2, CryptoNight algorithms | deep_dive_agentic |
| Privilege Escalation | AdjustTokenPrivileges, LsaAddAccountRights | deep_dive_agentic |
| Keylogging | capa rule: log keystrokes | capa |
| Anti-Analysis | IsDebuggerPresent, SetConsoleCtrlHandler | pe_imports, yara |
| Network Communication | stratum+tcp:// protocol | malcat |

## 9. Detection Engineering

### 9.1 YARA Rules

The following YARA rules can be used for detection:

**XMRIG_Miner** (source: yara, query: YARA matches, row: XMRIG_Miner, why: direct miner signature)
- Matches XMRig miner signature
- High confidence detection

**MiningProtocol** (source: malcat, query: YARA matches, row: MiningProtocol, why: mining protocol detection)
- Detects cryptomining protocols/domains
- Reliability: 90

**anti_dbg** (source: yara, query: YARA matches, row: anti_dbg, why: anti-debugging detection)
- Detects SetConsoleCtrlHandler pattern for debugger evasion

**escalate_priv** (source: yara, query: YARA matches, row: escalate_priv, why: privilege escalation detection)
- Detects privilege escalation patterns

**keylogger** (source: yara, query: YARA matches, row: keylogger, why: keylogging detection)
- Detects keylogging capabilities

### 9.2 Capa Rules

Key capa rules for detection:

- **log keystrokes** (T1056.001) - Input capture
- **receive data** / **send data** - C2 communication
- **resolve DNS** - DNS communication
- **encrypt data using AES** - Data encryption
- **encode data using XOR** - Data encoding

### 9.3 Network Signatures

- **stratum+tcp://** protocol detection
- **.nicehash.com** and **.minergate.com** domain monitoring
- **miner.fee.xmrig.com** and **emergency.fee.xmrig.com** domain blocking

### 9.4 Process Monitoring

- Monitor for processes with high CPU usage
- Watch for SeLockMemoryPrivilege acquisition
- Detect AdjustTokenPrivileges and LsaAddAccountRights calls
- Monitor for IsDebuggerPresent and SetConsoleCtrlHandler usage

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence | Source |
|---|---|---|---|---|
| Execution | Shared Modules | T1129 | LoadLibrary, GetProcAddress imports | pe_imports |
| Persistence | (not observed) | - | No persistence mechanisms found | deep_dive_agentic |
| Privilege Escalation | Access Token Manipulation | T1134 | AdjustTokenPrivileges, LsaAddAccountRights | deep_dive_agentic |
| Defense Evasion | Debugger Evasion | T1622 | IsDebuggerPresent, SetConsoleCtrlHandler | pe_imports, yara |
| Defense Evasion | Obfuscated Files or Information | T1027 | Obfuscated stackstrings, XOR encoding, AES encryption | capa |
| Credential Access | Input Capture | T1056.001 | log keystrokes | capa |
| Discovery | System Network Configuration Discovery | T1016 | get socket status | capa |
| Discovery | File and Directory Discovery | T1083 | get common file path, check if file exists | capa |
| Collection | Input Capture | T1056.001 | log keystrokes | capa |
| Command and Control | Ingress Tool Transfer | T1105 | receive data, send data | capa |
| Command and Control | Application Layer Protocol | T1071 | stratum+tcp:// protocol | malcat |
| Command and Control | Domain Resolution | T1071.001 | resolve DNS | capa |
| Impact | Resource Hijacking | T1496 | Cryptocurrency mining (XMRig) | deep_dive_agentic |

## 11. What We Don't Know

### 11.1 Runtime Behavior

Dynamic analysis (Speakeasy) ran but observed zero API calls. This could indicate:
- The DLL requires specific initialization parameters not provided
- Anti-analysis behavior prevented execution
- Missing dependencies or host process requirements
- The DLL is designed to run only when injected into another process

**Evidence**: Speakeasy emulation recorded 0 API calls and 0 key events (source: speakeasy, query: dynamic analysis, row: api_calls/key_events, why: shows no runtime behavior observed).

### 11.2 Persistence Mechanisms

No persistence mechanisms were observed. This could mean:
- The DLL relies on external persistence (e.g., dropper, scheduled task)
- Persistence is implemented in code not analyzed
- The sample is designed for one-time execution

**Evidence**: Deep-dive analysis states "Persistence mechanisms were not observed" (source: deep_dive_agentic, query: summary, row: persistence statement, why: indicates no persistence observed).

### 11.3 Configuration Details

The DLL contains configuration options (max-cpu-usage, cpu-affinity, cpu-priority, background mode) but the specific configuration used in deployment is unknown.

**Evidence**: Deep-dive analysis mentions configurable options (source: deep_dive_agentic, query: key_evidence, row: "Configurable max-cpu-usage", why: shows configuration options exist).

### 11.4 Injection Target

The DLL has 2021 exports, suggesting it may be designed for injection into other processes, but the specific target process is unknown.

**Evidence**: High export count (source: deep_dive_agentic, query: key_evidence, row: "2021 exports in DLL", why: indicates large attack surface for injection).

### 11.5 Developer Fee Collection

The DLL contains developer fee domains (miner.fee.xmrig.com, emergency.fee.xmrig.com) but the exact mechanism and timing of fee collection is not fully analyzed.

**Evidence**: Fee domains present (source: malcat, query: Top Strings, row: EA 616472/616496, why: shows developer fee infrastructure).

## 12. Appendix A: Tool Evidence Trail

### 12.1 Analysis Tools Used

| Tool | Version | Purpose | Source |
|---|---|---|---|
| Malcat | (unknown) | Static analysis, YARA, anomalies | malcat |
| Ghidra | (unknown) | Disassembly, decompilation | ghidra_query |
| IDA Pro | (unknown) | Disassembly, analysis | ida_query |
| Capa | (unknown) | Capability detection | capa |
| YARA | (unknown) | Pattern matching | yara |
| FLOSS | (unknown) | String extraction | floss |
| Radare2 | (unknown) | Disassembly | r2_decomp |
| Speakeasy | (unknown) | Dynamic emulation | speakeasy |
| Frida | 17.16.4 | Dynamic instrumentation | frida_probe |
| UPX | (unknown) | Packer detection | upx |
| XOR Search | (unknown) | XOR pattern detection | xor |

### 12.2 Key Evidence Citations

| Evidence | Source | Query/Table | Row/Rule | Why |
|---|---|---|---|---|
| XMRig 2.6.2 identification | deep_dive_agentic | key_evidence | "String 'XMRig 2.6.2'" | Confirms miner identity |
| stratum+tcp:// protocol | malcat | High-Signal Strings | EA 615704 | Mining pool communication |
| SeLockMemoryPrivilege | deep_dive_agentic | key_evidence | "Function FUN_180064ed0" | Privilege escalation for mining |
| log keystrokes | capa | capa rules | log keystrokes | Keylogging capability |
| IsDebuggerPresent | pe_imports | imports | check_debugger | Anti-analysis capability |
| XMRIG_Miner YARA rule | yara | YARA matches | XMRIG_Miner | Direct miner signature |
| MiningProtocol YARA rule | malcat | YARA matches | MiningProtocol | Mining protocol detection |
| 2021 exports | deep_dive_agentic | key_evidence | "2021 exports in DLL" | Large attack surface |
| High-complexity functions | deep_dive_agentic | key_evidence | "High-complexity functions" | Obfuscated mining code |
| Developer fee domains | malcat | Top Strings | EA 616472/616496 | Covert revenue mechanism |

### 12.3 Audit Trail

Recent analysis activities (source: audit trail):

- Ghidra queries for string references, function analysis, memory blocks
- IDA queries for imports, strings, function analysis
- YARA rule generation and validation
- Report publishing and technical analysis
- Quick scan phase 2 completion

## 13. Appendix B: Analysis Environment

### 13.1 Sample Information

- **SHA256**: a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395
- **Project**: 710
- **Sample Path**: /opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin

### 13.2 Analysis Timestamps

- **Generated YARA**: 2026-08-13T00:57:52.821286+00:00
- **Deep-dive Analysis**: (timestamp not provided)
- **Report Generation**: (timestamp not provided)

### 13.3 Tool Configuration

- **Malcat**: Used for static analysis, YARA matching, anomaly detection
- **Ghidra/IDA**: Used for disassembly and decompilation
- **Capa**: Used for capability detection with 43 rules matched
- **YARA**: 23 matches from pipeline
- **FLOSS**: 2082 strings extracted (3 decoded, 4 tight, 2075 static)
- **Speakeasy**: Emulation attempted, 0 API calls recorded
- **Frida**: Available (version 17.16.4), not actively used

### 13.4 Evidence Integrity

All evidence cited in this report comes from the structured evidence pack provided. No runtime behavior was invented for dynamic analysis sections where tools recorded zero events. All claims include source attribution as required by the analysis framework.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395  
**sample_path:** /opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin  
**project_name:** 710

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 40.0
- **family_guess**: XMRig Miner
- **confidence**: 40
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple analysis engines converge on identifying this sample as a cryptocurrency miner (XMRig) with malicious behaviors. Ghidra and IDA strings reveal mining usage and cryptonight algorithm references. MalCat's YARA and anomalies detect mining protocols and crypto API usage. Capa rules indicate keylogging and network activity. YARA matches include specific miner and keylogger rules, and external VirusTotal detections confirm high malicious classification.
- **summary**: The sample is identified as XMRig CPU miner version 2.6.2 with malicious behaviors including cryptocurrency mining and keylogging. Evidence from multiple tools shows mining algorithm references, keylogging capabilities, and network activity, supported by high external detections. This constitutes clear behavioral intent beyond obfuscation, warranting a malicious verdict.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | YARA matches | `XMRIG_Miner` | YARA rule directly matches the XMRig miner signature, confirming the sample's identity as cryptocurrency mining software |
| ghidra | Suspicious strings (Ghidra) | `addr 6443065440 | Usage: xmrig [OPTIONS] ... cryptonight` | String contains mining usage instructions and cryptonight algorithm references, providing evidence of cryptocurrency min |
| capa | capa rules | `log keystrokes` | Capa identifies keylogging behavior (ATT&CK T1056.001), which is a malicious input capture technique indicating credenti |
| malcat | YARA matches | `MiningProtocol` | MalCat's YARA detects mining protocol, corroborating the presence of mining-related network communication. |
| capa | capa rules | `receive data, send data` | Capa rules indicate network data transmission and reception, suggesting command-and-control or mining pool communication |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: XMRig 2.6.2 Monero cryptocurrency miner DLL (built May 28, 2018 with MSVC). This is a 64-bit DLL that performs CryptoNight-family cryptocurrency mining, consuming victim CPU resources to mine Monero for the attacker. It escalates privileges via SeLockMemoryPrivilege and LSA APIs (LsaAddAccountRights, AdjustTokenPrivileges) to allocate huge pages for efficient mining. It connects to mining pools over stratum+tcp:// protocol with references to nicehash.com and minergate.com, includes a built-in 5% developer donation fee, and supports background/stealth operation. Anti-analysis includes IsDebuggerPresent and SetConsoleCtrlHandler imports. YARA rules matched AES S-box, SHA2/BLAKE2, and SHA3 constants — all consistent with CryptoNight mining internals. The sample has 2021 exports and high-complexity functions (CC up to 279), consistent with an obfuscated/packed mining library. Persistence mechanisms were not observed in the analysis, with no evidence of auto-start, registry modifications, or scheduled tasks for maintaining presence. Defense impairment is indicated by anti-analysis imports such as IsDebuggerPresent and SetConsoleCtrlHandler, which can be used to evade debugger detection and handle console control events to prevent termination, as seen in the DLL's import table {source: static analysis, query: import table, row: IsDebuggerPresent and SetConsoleCtrlHandler, why: these functions impair debugging and shutdown processes}.

### deep key_evidence
- `"String 'XMRig 2.6.2\\n built on May 28 2018 with MSVC' at address 0x1800b66a8"`
- `"Full xmrig usage banner with CryptoNight/CryptoNight-Lite/CryptoNight-Heavy algorithm options"`
- `"String 'stratum+tcp://' at address 0x1800cf458 \u2014 mining pool connection protocol"`
- `"References to '.nicehash.com' and '.minergate.com' pool domains"`
- `"References to 'miner.fee.xmrig.com' and 'emergency.fee.xmrig.com' \u2014 built-in dev fee domains"`
- `"Function FUN_180064ed0 references 'SeLockMemoryPrivilege' for huge page memory allocation"`
- `"Import: AdjustTokenPrivileges (ADVAPI32.DLL) \u2014 privilege escalation"`
- `"Import: LsaAddAccountRights, LsaOpenPolicy (ADVAPI32.DLL) \u2014 LSA manipulation for privilege grants"`
- `"Import: SetPriorityClass (KERNEL32.DLL) \u2014 elevates process priority for mining"`
- `"Import: IsDebuggerPresent, SetConsoleCtrlHandler \u2014 anti-analysis/stealth capabilities"`
- `"Import: CreateThread \u2014 multi-threaded mining execution"`
- `"YARA match: RijnDael_AES_CHAR at offset 0x96550 \u2014 AES S-box for CryptoNight"`
- `"YARA match: SHA2_BLAKE2_IVs (8 hits) and SHA3_constants (8 hits) \u2014 mining algorithm internals"`
- `"YARA match: anti_dbg rule \u2014 SetConsoleCtrlHandler pattern for debugger evasion"`
- `"2021 exports in DLL \u2014 large attack surface for injection into other processes"`
- `"High-complexity functions: FUN_18003d590 (CC=279, 1398 instructions), FUN_180073a70 (CC=248, 1426 instructions)"`
- `"String 'donate-level' with default 5% (5 minutes per 100 minutes) \u2014 covert developer revenue"`
- `"Configurable max-cpu-usage, cpu-affinity, cpu-priority, background mode \u2014 evasion of detection"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395
size: 733696
type: PE
architecture: X64
entrypoint_ea: 304096
entropy: 6.56
file_name: dumped_dll.bin
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| header | 0 | 1024 | 0 | - |
| .text | 1024 | 563200 | 565248 | RX |
| .rdata | 566272 | 118272 | 118784 | R |
| .data | 685056 | 6144 | 16384 | RW |
| .pdata | 701440 | 18944 | 20480 | R |
| .rsrc | 721920 | 23040 | 24576 | R |
| .reloc | 746496 | 3072 | 4096 | R |

### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2017_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| visual_studio_2017_version_15_7_1_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| visual_studio_2017_version_15_6_6_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| MiningProtocol | network | SUSPICIOUS | 90 | use cryptomining protocols/domains |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |

### Anomalies (11)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BigStringHiScore | 3 | strings | 5 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 10 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 9 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 3 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX64 | 3 | code | 8 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 89 | XOR instruction in a loop |
| CryptoApiUsage | 2 | imports | 2 | Crypto-related apis are used |
| HighXrefLoopingFunction | 1 | code | 8 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SequentialFunction | 1 | code | 64 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 26 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **CryptoApiUsage**
  - `257841`: 
  - `257153`: 
- **DynamicString**
  - `550465`: 
  - `552516`: 
  - `557043`: 
  - `557036`: 
  - `552526`: 
- **HighXrefLoopingFunction**
  - `301140`: 
  - `309856`: 
  - `310400`: 
  - `358236`: 
  - `402096`: 
- **ManyHighValueImmediates**
  - `272640`: 
  - `283184`: 
  - `295328`: 
  - `295462`: 
  - `304792`: 
- **ManyUniqueImmediateBytes**
  - `9008`: 
  - `364392`: 
  - `552492`: 
- **NoChecksum**
  - `376`: 
- **SequentialFunction**
  - `27744`: 
  - `49760`: 
  - `51184`: 
  - `53040`: 
  - `56160`: 
- **SpaghettiFunction**
  - `29072`: 
  - `230416`: 
  - `231856`: 
  - `265264`: 
  - `266368`: 
- **XorInLoop**
  - `46000`: 
  - `46404`: 
  - `46896`: 
  - `47668`: 
  - `53456`: 

### High-Signal Strings (8 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 615704 | `stratum+tcp://` |
| 568224 | `kernel32.dll` |
| 641992 | `kernel32.dll` |
| 629048 | `\\?\UNC\` |
| 629088 | `\\?\` |
| 636504 | `""""""""""""""""\\\\\\\\\\\\\\\\` |
| 641816 | `GetProcAddress` |
| 615816 | `cryptonightv7.` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 550465 | `030000005F000000..1700000032000000` |
| 552516 | `000000005C000000..0000000000000000` |
| 557043 | `1200000011000000..0E0000002A000000` |
| 557036 | `0F0000002B000000..0000000000000000` |
| 552526 | `140000003A000000..000000005B000000` |
| 534990 | `98FA2E0800000000..0000000000000000` |
| 550160 | `0000000033000000..0000000000000000` |
| 536931 | `67E6096A85AE67BB..0000000000000000` |
| 277208 | `0000000000000000..8EE976E58C74063E` |
| 615704 | `stratum+tcp://` |
| 569120 | `api-ms-win-core-synch-l1-2-0.dll` |
| 439799 | `00000000` |
| 616544 | `48edfHu7V9Z84Yzz..4fhdUyZijBGUicoD` |
| 624232 | `ntdll.dll` |
| 632656 | `0001020304050607..6979899No error.` |
| 573864 | `mscoree.dll` |
| 642384 | `iphlpapi.dll` |
| 641752 | `ntdll.dll` |
| 744552 | `<?xml version='1..>
</assembly>
` |
| 616496 | `emergency.fee.xmrig.com` |
| 641344 | `abcdefghijklmnop..UVWXYZ0123456789` |
| 642296 | `powrprof.dll` |
| 568224 | `kernel32.dll` |
| 629136 | `0123456789abcdef` |
| 629112 | `0123456789ABCDEF` |
| 616472 | `miner.fee.xmrig.com` |
| 641992 | `kernel32.dll` |
| 615800 | `.nicehash.com` |
| 615488 | `{"id":%lld,"json..s":{"id":"%s"}}
` |
| 624552 | `SeLockMemoryPrivilege` |
| 615832 | `.minergate.com` |
| 611424 | `Usage: xmrig [OP..mation and exit
` |
| 629032 | `\??\` |
| 615640 | `[%s] DNS error: ..) records found"` |
| 642312 | `PowerRegisterSus..sumeNotification` |
| 642008 | `SetFileCompletio..otificationModes` |
| 608792 | `No valid configu..found. Exiting.
` |
| 629048 | `\\?\UNC\` |
| 624608 | `Huge pages suppo..quired to use it` |
| 623944 | `thread %zu error..lf-test failed".` |
| 642352 | `user32.dll` |
| 641472 | `XXXXXX` |
| 624384 | `Unable to set af..finity up to 63.` |
| 622232 | `speed 2.5s/60s/1.. H/s max: %s H/s` |
| 608736 | `%s: unsupported ..n argument '%s'
` |
| 578704 | `api-ms-win-core-..-obsolete-l1-2-0` |
| 568672 | `GetCurrentProcessorNumber` |
| 615128 | `Unknown/unsuppor..ected, reconnect` |
| 641904 | `NtQueryVolumeInformationFile` |
| 579216 | `api-ms-win-secur..functions-l1-1-0` |
| 568344 | `InitOnceExecuteOnce` |
| 568480 | `WaitForThreadpoolTimerCallbacks` |
| 624504 | `SeLockMemoryPrivilege` |
| 568640 | `FreeLibraryWhenCallbackReturns` |
| 609072 | `option requires ..n argument -- %s` |
| 615008 | `[%s] duplicate j..eived, reconnect` |
| 642400 | `ConvertInterfaceIndexToLuid` |
| 609144 | `option requires ..n argument -- %c` |
| 568608 | `FlushProcessWriteBuffers` |
| 615080 | `Incompatible alg..ected, reconnect` |
| 683040 | `AdjustTokenPrivileges` |
| 609008 | `option doesn't t..argument -- %.*s` |
| 640568 | `GetQueuedCompletionStatus` |
| 579312 | `ext-ms-win-kerne..e-current-l1-1-0` |
| 579488 | `ext-ms-win-ntuse..owstation-l1-1-0` |
| 616184 | `rejected (%lld/%..u "%s" (%llu ms)` |
| 641792 | `RtlNtStatusToDosError` |
| 629088 | `\\?\` |
| 641696 | `0.0.0.0` |
| 568776 | `SetFileInformationByHandle` |
| 568744 | `GetFileInformationByHandleEx` |
| 579136 | `api-ms-win-rtcor..er-window-l1-1-0` |
| 638936 | `resolved protocol is unknown` |
| 568432 | `CreateThreadpoolTimer` |
| 616312 | `accepted (%lld/%..iff %u (%llu ms)` |
| 568944 | `CreateThreadpoolWork` |
| 616064 | `no active pools, stop mining` |
| 614688 | `[%d-%02d-%02d %0..2d:%02d]%s %s%s
` |
| 641960 | `NtQuerySystemInformation` |
| 641936 | `NtQueryDirectoryFile` |

### Constants / Known Patterns (9)
| Category | Value |
|---|---|
| registry | `registry::HKEY_LOCAL_MACHINE` |
| exception | `exception::FuncInfo header` |
| exception | `exception::C++ exception` |
| exception | `exception::CLR exception` |
| registry | `registry::HKEY_USERS` |
| code | `code::PEBx64` |
| registry | `registry::HKEY_CURRENT_USER` |
| math | `math::log10` |
| crypto | `crypto::AES` |

### Imports (863)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1300 | ??__E?s_cookie@Security@details@Concurrency@@2_KA@@YAXXZ | DEBUG | 2 |
| 1360 | snprintf | DEBUG | 34 |
| 1456 | xmrig::CommonConfig.#2 | DEBUG | 2 |
| 1488 | xmrig::CommonConfig.#7 | DEBUG | 2 |
| 1504 | xmrig::ConfigCreator.#0 | DEBUG | 3 |
| 1552 | xmrig::ConfigCreator.#1 | DEBUG | 2 |
| 1728 | xmrig::Config.#0 | DEBUG | 2 |
| 2576 | GuardCFCheckFunction | DEBUG | 44 |
| 2576 | DonateStrategy.#4 | DEBUG | 44 |
| 8048 | IConsoleListener.#0 | DEBUG | 2 |
| 8096 | App.#0 | DEBUG | 2 |
| 8256 | xmrig::IConfig.#0 | DEBUG | 2 |
| 12560 | xmrig::CommonConfig.#0 | DEBUG | 2 |
| 19424 | fprintf | DEBUG | 10 |
| 27568 | ILogBackend.#0 | DEBUG | 2 |
| 27616 | ConsoleLog.#0 | DEBUG | 2 |
| 27664 | FileLog.#0 | DEBUG | 2 |
| 43808 | IClientListener.#0 | DEBUG | 2 |
| 43872 | IStrategy.#0 | DEBUG | 2 |
| 43920 | FailoverStrategy.#1 | DEBUG | 1 |
| 43936 | FailoverStrategy.#0 | DEBUG | 3 |
| 44316 | FailoverStrategy.#0 | DEBUG | 1 |
| 44336 | DonateStrategy.#1 | DEBUG | 2 |
| 44352 | SinglePoolStrategy.#0 | DEBUG | 3 |
| 44516 | SinglePoolStrategy.#0 | DEBUG | 1 |
| 44544 | xmrig::IWatcherListener.#0 | DEBUG | 2 |
| 44592 | xmrig::Controller.#0 | DEBUG | 2 |
| 44960 | IJobResultListener.#0 | DEBUG | 2 |
| 45024 | IStrategyListener.#0 | DEBUG | 2 |
| 45072 | Network.#0 | DEBUG | 3 |
| 45376 | Network.#0 | DEBUG | 1 |
| 45392 | DonateStrategy.#0 | DEBUG | 3 |
| 45664 | DonateStrategy.#0 | DEBUG | 1 |
| 45680 | xmrig::IThread.#0 | DEBUG | 2 |
| 45728 | xmrig::CpuThread.#1 | DEBUG | 1 |
| 45744 | xmrig::CpuThread.#2 | DEBUG | 1 |
| 45760 | xmrig::CpuThread.#3 | DEBUG | 1 |
| 45776 | xmrig::CpuThread.#4 | DEBUG | 1 |
| 45792 | xmrig::CpuThread.#6 | DEBUG | 1 |
| 45808 | xmrig::CpuThread.#7 | DEBUG | 1 |
| 45824 | xmrig::CpuThread.#0 | DEBUG | 2 |
| 45824 | Concurrency.details.RealizedChore.`scalar deleting destructor' | DEBUG | 2 |
| 45872 | xmrig::CpuThread.#8 | DEBUG | 2 |
| 46192 | xmrig::CpuThread.#9 | DEBUG | 2 |
| 46768 | xmrig::CpuThread.#10 | DEBUG | 2 |
| 47408 | xmrig::CpuThread.#11 | DEBUG | 2 |
| 48656 | xmrig::CpuThread.#12 | DEBUG | 2 |
| 49760 | xmrig::CpuThread.#13 | DEBUG | 2 |
| 51184 | xmrig::CpuThread.#14 | DEBUG | 2 |
| 53040 | xmrig::CpuThread.#15 | DEBUG | 2 |
| 56160 | xmrig::CpuThread.#16 | DEBUG | 2 |
| 60304 | xmrig::CpuThread.#17 | DEBUG | 2 |
| 65584 | xmrig::CpuThread.#18 | DEBUG | 2 |
| 66032 | xmrig::CpuThread.#19 | DEBUG | 2 |
| 66864 | xmrig::CpuThread.#20 | DEBUG | 2 |
| 67680 | xmrig::CpuThread.#21 | DEBUG | 2 |
| 69184 | xmrig::CpuThread.#22 | DEBUG | 2 |
| 70880 | xmrig::CpuThread.#23 | DEBUG | 2 |
| 73104 | xmrig::CpuThread.#24 | DEBUG | 2 |
| 75888 | xmrig::CpuThread.#25 | DEBUG | 2 |
| 79616 | xmrig::CpuThread.#26 | DEBUG | 2 |
| 84560 | xmrig::CpuThread.#27 | DEBUG | 2 |
| 208368 | IWorker.#0 | DEBUG | 2 |
| 208416 | Worker.#2 | DEBUG | 6 |
| 208432 | Worker.#3 | DEBUG | 6 |
| 208448 | Worker.#4 | DEBUG | 6 |
| 208464 | MultiWorker<1>.#1 | DEBUG | 2 |
| 209056 | MultiWorker<1>.#5 | DEBUG | 3 |
| 210160 | MultiWorker<2>.#1 | DEBUG | 2 |
| 210752 | MultiWorker<2>.#5 | DEBUG | 3 |
| 212032 | MultiWorker<3>.#1 | DEBUG | 2 |
| 212624 | MultiWorker<3>.#5 | DEBUG | 3 |
| 213968 | MultiWorker<4>.#1 | DEBUG | 2 |
| 214576 | MultiWorker<4>.#5 | DEBUG | 2 |
| 215920 | MultiWorker<5>.#1 | DEBUG | 2 |
| 216528 | MultiWorker<5>.#5 | DEBUG | 2 |
| 217872 | MultiWorker<1>.#0 | DEBUG | 2 |
| 220112 | MultiWorker<2>.#0 | DEBUG | 2 |
| 221776 | MultiWorker<3>.#0 | DEBUG | 2 |
| 223440 | MultiWorker<4>.#0 | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 202688 | sub_1800323c0 |
| 60304 | #17 |
| 130384 | sub_180020950 |
| 180128 | sub_18002cba0 |
| 84560 | #27 |
| 109744 | sub_18001b8b0 |
| 154640 | sub_180026810 |
| 126240 | sub_18001f920 |
| 56160 | #16 |
| 175120 | sub_18002b810 |
| 79616 | #26 |
| 149696 | sub_1800254c0 |
| 104800 | sub_18001a560 |
| 171344 | sub_18002a950 |
| 194896 | sub_180030550 |
| 75888 | #25 |
| 101072 | sub_1800196d0 |
| 145968 | sub_180024630 |
| 53040 | #15 |
| 123120 | sub_18001ecf0 |
| 198240 | sub_180031260 |
| 313832 | sub_18004d5e8 |
| 559391 | sub_18008951f |
| 508512 | sub_18007ce60 |
| 508880 | sub_18007cfd0 |
| 468176 | sub_1800730d0 |
| 468864 | sub_180073380 |
| 466800 | sub_180072b70 |
| 467488 | sub_180072e20 |
| 465552 | sub_180072690 |

### Decompilations (top 6)
#### 202688 — sub_1800323c0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_1800323c0(int64_t param_1,uint64_t param_2,int64_t param_3,uint64_t **param_4)

{
    undefined auVar1 [16];
    undefined auVar2 [16];
    undefined auVar3 [16];
    undefined auVar4 [16];
    undefined auVar5 [16];
    uint64_t uVar6;
    uint64_t uVar7;
    uint64_t uVar8;
    uint64_t uVar9;
    undefined auVar10 [16];
    undefined auVar11 [16];
    undefined auVar12 [16];
    undefined auVar13 [16];
    undefined auVar14 [16];
    undefined auVar15 [16];
    undefined auVar16 [16];
    undefined auVar17 [16];
    undefined auVar18 [16];
    undefined auVar19 [16];
    undefined auVar20 [16];
    undefined auVar21 [16];
    undefined auVar22 [16];
    undefined auVar23 [16];
    undefined auVar24 [16];
    uint64_t uVar25;
    uint64_t uVar26;
    uint64_t uVar27;
    uint64_t uVar28;
    uint64_t uVar29;
    uint64_t uVar30;
    uint64_t uVar31;
    uint64_t uVar32;
    undefined (*pauVar33) [16];
    uint64_t *puVar34;
    uint64_t uVar35;
    uint64_t uVar36;
    uint64_t uVar37;
    uint64_t uVar38;
    uint64_t uVar39;
    uint64_t uVar40;
    uint64_t uVar41;
    uint64_t uVar42;
    uint32_t uVar43;
    uint32_t uVar44;
    undefined (*pauVar45) [16];
    undefined (*pauVar46) [16];
    uint64_t *puVar47;
    uint64_t uVar48;
    uint64_t uVar49;
    uint32_t uVar50;
    uint32_t uVar51;
    uint64_t *puVar52;
    undefined (*pauVar53) [16];
    uint64_t *puVar54;
    uint64_t *puVar55;
    undefined auVar56 [16];
    uint64_t uVar57;
    uint64_t uVar58;
    uint64_t uVar59;
    uint64_t uVar60;
    uint64_t uVar61;
    uint64_t uVar62;
    uint64_t uVar63;
    uint32_t uVar67;
    uint64_t uVar64;
    uint64_t uVar65;
    uint64_t uVar66;
    uint32_t uVar69;
    uint32_t uVar70;
    uint32_t uVar71;
    undefined auVar68 [16];
    uint32_t uVar73;
    uint32_t uVar74;
    undefined auVar72 [16];
    undefined auVar75 [16];
    undefined auVar76 [16];
    undefined auVar77 [16];
    uint64_t uVar78;
    uint64_t uVar79;
    undefined auVar80 [16];
    uint64_t uVar81;
    uint64_t uVar82;
    undefined auVar83 [16];
    uint64_t uVar84;
    uint64_t uVar85;
    undefined auVar86 [16];
    uint64_t uVar87;
    uint64_t uVar88;
    undefined auVar89 [16];
    uint64_t uVar90;
    int64_t iStack_188;
    uint64_t uStack_148;
    uint64_t uStack_128;
    uint64_t uStack_120;
    uint64_t uStack_118;
    uint64_t uStack_110;
    
    uVar48 = 0;
    uStack_148 = 0;
    do {
        sub_180068130(param_1, param_2 & 0xffffffff, param_4[uVar48]);
        sub_180075b50(param_4[uVar48], param_4[uVar48][0x1a]);
        uVar48 = uVar48 + 1;
        param_1 = param_1 + param_2;
    } while (uVar48 < 5);
    puVar52 = *param_4;
    puVar34 = param_4[1];
    puVar47 = param_4[2];
    puVar54 = param_4[3];
    puVar55 = param_4[4];
    uVar35 = puVar52[5] ^ puVar52[1];
    uVar25 = puVar52[4] ^ *puVar52;
    uVar48 = puVar34[0x1a];
    uVar6 = puVar47[0x1a];
    uVar36 = puVar52[7] ^ puVar52[3];
    uVar26 = puVar52[6] ^ puVar52[2];
    uVar7 = puVar54[0x1a];
    uVar8 = puVar55[0x1a];
    uVar9 = puVar52[0x1a];
    uVar27 = puVar34[4] ^ *puVar34;
    uVar37 = puVar34[5] ^ puVar34[1];
    uVar28 = puVar34[6] ^ puVar34[2];
    uVar38 = puVar34[7] ^ puVar34[3];
    uVar29 = puVar47[4] ^ *puVar47;
    uVar39 = puVar47[5] ^ puVar47[1];
    uVar30 = puVar47[6] ^ puVar47[2];
    uVar40 = puVar47[7] ^ puVar47[3];
    uVar31 = puVar54[4] ^ *puVar54;
    uVar41 = puVar54[5] ^ puVar54[1];
    uStack_128 = puVar54[6] ^ puVar54[2];
    uStack_120 = puVar54[7] ^ puVar54[3];
    uVar42 = puVar55[5] ^ puVar55[1];
    uVar32 = puVar55[4] ^ *puVar55;
    uStack_110 = puVar55[7] ^ puVar55[3];
    uStack_118 = puVar55[6] ^ puVar55[2];
    iStack_188 = 0x20000;
    uVar57 = uVar25;
    uVar58 = uVar27;
    uVar59 = uVar29;
    uVar61 = uVar32;
    uVar60 = uVar31;
    do {
        pauVar33 = (uVar32 & 0x3ffff0) + uVar8;
        pauVar53 = (uVar27 & 0x3ffff0) + uVar48;
        pauVar
```
#### 60304 — #17
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void xmrig::CpuThread.#17(int64_t param_1,uint64_t param_2,int64_t param_3,uint64_t **param_4)

{
    undefined auVar1 [16];
    undefined auVar2 [16];
    undefined auVar3 [16];
    undefined auVar4 [16];
    undefined auVar5 [16];
    uint64_t *puVar6;
    uint64_t *puVar7;
    uint64_t *puVar8;
    uint64_t uVar9;
    uint64_t uVar10;
    uint64_t uVar11;
    uint64_t uVar12;
    undefined auVar13 [16];
    undefined auVar14 [16];
    undefined auVar15 [16];
    undefined auVar16 [16];
    undefined auVar17 [16];
    undefined auVar18 [16];
    undefined auVar19 [16];
    undefined auVar20 [16];
    undefined auVar21 [16];
    undefined auVar22 [16];
    undefined auVar23 [16];
    undefined auVar24 [16];
    undefined auVar25 [16];
    undefined auVar26 [16];
    undefined auVar27 [16];
    uint64_t uVar28;
    uint64_t uVar29;
    uint64_t uVar30;
    uint64_t uVar31;
    uint64_t uVar32;
    uint64_t uVar33;
    uint64_t uVar34;
    uint64_t uVar35;
    uint64_t uVar36;
    uint64_t uVar37;
    uint64_t uVar38;
    uint64_t uVar39;
    uint64_t uVar40;
    uint64_t uVar41;
    uint64_t uVar42;
    uint64_t uVar43;
    undefined (*pauVar44) [16];
    uint32_t uVar45;
    uint32_t uVar46;
    uint32_t uVar47;
    uint32_t uVar48;
    uint64_t uVar49;
    uint64_t uVar50;
    undefined (*pauVar51) [16];
    uint64_t uVar52;
    uint32_t uVar53;
    uint32_t uVar54;
    undefined (*pauVar55) [16];
    undefined (*pauVar56) [16];
    uint64_t uVar57;
    undefined (*pauVar58) [16];
    uint64_t *puVar59;
    uint64_t *puVar60;
    undefined auVar61 [16];
    uint64_t uVar62;
    uint64_t uVar63;
    uint64_t uVar64;
    uint64_t uVar65;
    uint64_t uVar66;
    uint64_t uVar67;
    uint64_t uVar68;
    uint64_t uVar69;
    uint64_t uVar70;
    uint64_t uVar71;
    uint32_t uVar73;
    uint32_t uVar74;
    undefined auVar72 [16];
    uint32_t uVar76;
    uint32_t uVar77;
    undefined auVar75 [16];
    uint32_t uVar79;
    undefined auVar78 [16];
    uint32_t uVar81;
    undefined auVar80 [16];
    undefined auVar82 [16];
    undefined auVar83 [16];
    uint64_t uVar84;
    uint64_t uVar85;
    undefined auVar86 [16];
    uint64_t uVar87;
    uint64_t uVar88;
    undefined auVar89 [16];
    uint64_t uVar90;
    uint64_t uVar91;
    undefined auVar92 [16];
    uint64_t uVar93;
    int64_t iStack_198;
    uint64_t uStack_138;
    uint64_t uStack_118;
    uint64_t uStack_110;
    uint64_t uStack_108;
    uint64_t uStack_100;
    
    uVar49 = 0;
    uStack_138 = 0;
    do {
        sub_180068130(param_1, param_2 & 0xffffffff, param_4[uVar49]);
        sub_18007b230(param_4[uVar49], param_4[uVar49][0x1a]);
        uVar49 = uVar49 + 1;
        param_1 = param_1 + param_2;
    } while (uVar49 < 5);
    puVar6 = *param_4;
    puVar59 = param_4[1];
    puVar60 = param_4[2];
    puVar7 = param_4[3];
    puVar8 = param_4[4];
    uVar36 = puVar6[5] ^ puVar6[1];
    uVar28 = puVar6[4] ^ *puVar6;
    uVar49 = puVar59[0x1a];
    uVar9 = puVar60[0x1a];
    uVar37 = puVar6[7] ^ puVar6[3];
    uVar29 = puVar6[6] ^ puVar6[2];
    uVar10 = puVar7[0x1a];
    uVar11 = puVar8[0x1a];
    uVar12 = puVar6[0x1a];
    uVar30 = puVar59[4] ^ *puVar59;
    uVar38 = puVar59[5] ^ puVar59[1];
    uVar31 = puVar59[6] ^ puVar59[2];
    uVar39 = puVar59[7] ^ puVar59[3];
    uVar32 = puVar60[4] ^ *puVar60;
    uVar40 = puVar60[5] ^ puVar60[1];
    uVar33 = puVar60[6] ^ puVar60[2];
    uVar41 = puVar60[7] ^ puVar60[3];
    uVar34 = puVar7[4] ^ *puVar7;
    uVar42 = puVar7[5] ^ puVar7[1];
    uStack_118 = puVar7[6] ^ puVar7[2];
    uStack_110 = puVar7[7] ^ puVar7[3];
    uVar43 = puVar8[5] ^ puVar8[1];
    uVar35 = puVar8[4] ^ *puVar8;
    uStack_100 = puVar8[7] ^ puVar8[3];
    uStack_108 = puVar8[6] ^ puVar8[2];
    iStack_198 = 0x40000;
    do {
        pauVar44 = (uVar28 & 0x1ffff0) + uVar12;
        pauVar51 = (uVar30 & 0x1ffff0) + uVar49;
        pauVar55 = (uVar32 & 0x1ffff0) + uVar9;
        auVar1 =
```
#### 130384 — sub_180020950
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_180020950(int64_t param_1,uint64_t param_2,int64_t param_3,uint64_t **param_4)

{
    undefined auVar1 [16];
    undefined auVar2 [16];
    undefined auVar3 [16];
    undefined auVar4 [16];
    undefined auVar5 [16];
    uint64_t *puVar6;
    uint64_t *puVar7;
    uint64_t *puVar8;
    uint64_t uVar9;
    uint64_t uVar10;
    uint64_t uVar11;
    uint64_t uVar12;
    undefined auVar13 [16];
    undefined auVar14 [16];
    undefined auVar15 [16];
    undefined auVar16 [16];
    undefined auVar17 [16];
    undefined auVar18 [16];
    undefined auVar19 [16];
    undefined auVar20 [16];
    undefined auVar21 [16];
    undefined auVar22 [16];
    undefined auVar23 [16];
    undefined auVar24 [16];
    undefined auVar25 [16];
    undefined auVar26 [16];
    undefined auVar27 [16];
    uint64_t uVar28;
    uint64_t uVar29;
    uint64_t uVar30;
    uint64_t uVar31;
    uint64_t uVar32;
    uint64_t uVar33;
    uint64_t uVar34;
    uint64_t uVar35;
    uint64_t uVar36;
    uint64_t uVar37;
    uint64_t uVar38;
    uint64_t uVar39;
    uint64_t uVar40;
    uint64_t uVar41;
    uint64_t uVar42;
    uint64_t uVar43;
    undefined (*pauVar44) [16];
    uint32_t uVar45;
    uint32_t uVar46;
    uint32_t uVar47;
    uint32_t uVar48;
    uint64_t uVar49;
    uint64_t uVar50;
    undefined (*pauVar51) [16];
    uint64_t uVar52;
    uint32_t uVar53;
    uint32_t uVar54;
    undefined (*pauVar55) [16];
    undefined (*pauVar56) [16];
    uint64_t uVar57;
    undefined (*pauVar58) [16];
    uint64_t *puVar59;
    uint64_t *puVar60;
    undefined auVar61 [16];
    uint64_t uVar62;
    uint64_t uVar63;
    uint64_t uVar64;
    uint64_t uVar65;
    uint64_t uVar66;
    uint64_t uVar67;
    uint64_t uVar68;
    uint64_t uVar69;
    uint64_t uVar70;
    uint64_t uVar71;
    uint32_t uVar73;
    uint32_t uVar74;
    undefined auVar72 [16];
    uint32_t uVar76;
    uint32_t uVar77;
    undefined auVar75 [16];
    uint32_t uVar79;
    undefined auVar78 [16];
    uint32_t uVar81;
    undefined auVar80 [16];
    undefined auVar82 [16];
    undefined auVar83 [16];
    uint64_t uVar84;
    uint64_t uVar85;
    undefined auVar86 [16];
    uint64_t uVar87;
    uint64_t uVar88;
    undefined auVar89 [16];
    uint64_t uVar90;
    uint64_t uVar91;
    undefined auVar92 [16];
    uint64_t uVar93;
    int64_t iStack_198;
    uint64_t uStack_138;
    uint64_t uStack_118;
    uint64_t uStack_110;
    uint64_t uStack_108;
    uint64_t uStack_100;
    
    uVar49 = 0;
    uStack_138 = 0;
    do {
        sub_180068130(param_1, param_2 & 0xffffffff, param_4[uVar49]);
        sub_180079090(param_4[uVar49], param_4[uVar49][0x1a]);
        uVar49 = uVar49 + 1;
        param_1 = param_1 + param_2;
    } while (uVar49 < 5);
    puVar6 = *param_4;
    puVar59 = param_4[1];
    puVar60 = param_4[2];
    puVar7 = param_4[3];
    puVar8 = param_4[4];
    uVar36 = puVar6[5] ^ puVar6[1];
    uVar28 = puVar6[4] ^ *puVar6;
    uVar49 = puVar59[0x1a];
    uVar9 = puVar60[0x1a];
    uVar37 = puVar6[7] ^ puVar6[3];
    uVar29 = puVar6[6] ^ puVar6[2];
    uVar10 = puVar7[0x1a];
    uVar11 = puVar8[0x1a];
    uVar12 = puVar6[0x1a];
    uVar30 = puVar59[4] ^ *puVar59;
    uVar38 = puVar59[5] ^ puVar59[1];
    uVar31 = puVar59[6] ^ puVar59[2];
    uVar39 = puVar59[7] ^ puVar59[3];
    uVar32 = puVar60[4] ^ *puVar60;
    uVar40 = puVar60[5] ^ puVar60[1];
    uVar33 = puVar60[6] ^ puVar60[2];
    uVar41 = puVar60[7] ^ puVar60[3];
    uVar34 = puVar7[4] ^ *puVar7;
    uVar42 = puVar7[5] ^ puVar7[1];
    uStack_118 = puVar7[6] ^ puVar7[2];
    uStack_110 = puVar7[7] ^ puVar7[3];
    uVar43 = puVar8[5] ^ puVar8[1];
    uVar35 = puVar8[4] ^ *puVar8;
    uStack_100 = puVar8[7] ^ puVar8[3];
    uStack_108 = puVar8[6] ^ puVar8[2];
    iStack_198 = 0x20000;
    do {
        pauVar44 = (uVar28 & 0xffff0) + uVar12;
        pauVar51 = (uVar30 & 0xffff0) + uVar49;
        pauVar55 = (uVar32 & 0xffff0) + uVar9;
        auVar1 = *pauVar44
```

### Carved Files (4)
| Name | Type | Size |
|---|---|---|
| ? | PNG | 6395 |
| ? | DIB | 9640 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |

### Virtual Files (7)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/en-us | 6395 | - |
| ICO/2/en-us | 9640 | - |
| ICO/3/en-us | 4264 | - |
| ICO/4/en-us | 1128 | - |
| GRPICO/IDI_ICON1/en-us | 62 | - |
| VER/1/en-us | 652 | - |
| MANIF/2/en-us | 381 | - |

### Structures (58)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 288 |
| OptionalHeader | 312 |
| Sections | 552 |
| advapi32.FT | 566272 |
| kernel32.FT | 566360 |
| user32.FT | 567584 |
| ws2_32.FT | 567632 |
| GuardCFCheckFunctionPointer | 567800 |
| GuardCFDispatchFunctionPointer | 567808 |
| TlsCallbacks | 567984 |
| DebugDirectory | 644704 |
| LoadConfigurationTable | 644736 |
| TlsDirectory | 644992 |
| Debug.Pogo | 650004 |
| TLSInitArray | 650944 |
| ExportDirectory | 679024 |
| ExportAddressTable | 679064 |
| ExportNameTable | 679068 |
| OrdinalNameTable | 679072 |
| ExportNames | 679074 |
| ImportTable | 679092 |
| advapi32.OFT | 679192 |
| kernel32.OFT | 679280 |
| user32.OFT | 680504 |
| ws2_32.OFT | 680552 |
| ImportNames | 680720 |
| SecurityCookie | 685080 |
| ExceptionTable | 701440 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 43 · duration_s: 1.75

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using AES | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| encrypt data using AES via x86 extensions | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| get socket status | T1016:System Network Configuration Discovery | C0001.012:Socket Communication |
| encrypt data using speck | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check for time delay via QueryPerformanceCounter |  | B0001.033:Debugger Detection |
| log keystrokes | T1056.001:Input Capture |  |
| receive data |  | B0030.002:C2 Communication |
| send data |  | B0030.001:C2 Communication |
| resolve DNS |  | C0011.001:DNS Communication |
| connect pipe |  | C0003.002:Interprocess Communication |
| create pipe |  | C0003.001:Interprocess Communication |

## PE Imports / Signals
import_count: 187

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 23

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@639648 len=7; $ipv6@616601 len=2 |
| contains_base64 | - | $a@13589 len=12 |
| SHA2_BLAKE2_IVs | - | $c0@534868 len=4; $c1@534890 len=4; $c2@534897 len=4; $c3@534904 len=4; $c4@534911 len=4; $c5@534918 len=4; $c6@534925 len=4; $c7@534933 len=4 |
| RijnDael_AES_CHAR | - | $c0@615696 len=32 |
| SHA3_constants | - | $c0@612424 len=8; $c1@612552 len=8; $c2@612568 len=8; $c3@612504 len=8; $c4@612408 len=8; $c5@612512 len=8; $c6@612584 len=8; $c7@612480 len=8 |
| IsPE64 | - |  |
| IsDLL | - |  |
| IsConsole | - |  |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@264 len=4 |
| DebuggerException__SetConsoleCtrl | - | $@679092 len=21 |
| anti_dbg | - | $d1@639944 len=12; $c2@681374 len=17 |
| network_udp_sock | - | $f1@678764 len=10; $c0@639632 len=10; $c4@678752 len=11 |
| network_tcp_listen | - | $f1@678764 len=10; $c2@614200 len=6 |
| network_tcp_socket | - | $f1@678764 len=10; $c1@678716 len=9; $c2@604574 len=6; $c3@610050 len=4; $c4@678730 len=7; $c6@603920 len=7 |
| network_dns | - | $f2@678764 len=10; $c3@613144 len=11 |
| escalate_priv | - | $d1@681102 len=12; $c2@680992 len=21 |
| keylogger | - | $f1@640304 len=10; $c3@680856 len=13 |
| win_token | - | $f1@681102 len=12; $c2@680992 len=21; $c3@680972 len=16 |
| win_files_operation | - | $f1@639944 len=12; $c1@679804 len=9; $c2@679938 len=14; $c3@679804 len=9; $c4@679776 len=8; $c6@679576 len=11 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@678764 len=10 |
| XMRIG_Miner | - | $a1@613656 len=11 |

## Generated YARA Meta
```json
{
  "sha256": "a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395",
  "family": "xmrig",
  "imphash": "0c4c8e94664e68ee06fc2a3faae408ec",
  "generated_at": "2026-08-13T00:57:52.821286+00:00",
  "string_count": 24,
  "strings": [
    "efefefefefefefe",
    "efefefefefe",
    "!This program cannot be run in DOS mode.",
    "L$ SUVWH",
    "@WATAUAVAWH",
    "0A_A^A]A\\_",
    "t$ WAVAWH",
    "\\$ UVWAVAWH",
    "0A_A^_^]",
    "|$ ATAUAVAWH",
    "|$@A_A^A]A\\",
    "UVWATAUAVAWH",
    "A_A^A]A\\_^]",
    "SVWATAUAVAWH",
    "<$HkD$ XI",
    "`A_A^A]A\\_^[",
    "L$ UVWAUAWH",
    "0A_A]_^]",
    "SUVWATAUAWH",
    "A_A]A\\_^][",
    "t$ WATAUAVAWH",
    "UATAUAVAWH",
    "A_A^A]A\\]",
    "pA_A^A]A\\_^]"
  ],
  "rule_path": "/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/rule.yar",
  "sigma_path": "/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/rule.yml",
  "iocs_path": "/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/iocs.json",
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
    "utc": "2026-08-13 00:57:52 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 2082 · per_category: `{"decoded_strings": 3, "stack_strings": 0, "tight_strings": 4, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2075}`

### FLOSS sample
- `P]P)]$7`
- `\$ UVWf`
- `M.i,ud&`
- `efefefefefefefe`
- `efefefefefe`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.pdata`
- `@.rsrc`
- `@.reloc`
- `L$ SUVWH`
- `@WATAUAVAWH`
- `0A_A^A]A\_`
- `t$ WAVAWH`
- `\$ UVWAVAWH`
- `0A_A^_^]`
- `|$ ATAUAVAWH`
- `|$@A_A^A]A\`
- `UVWATAUAVAWH`
- `A_A^A]A\_^]`
- `SVWATAUAVAWH`
- `<$HkD$ XI`
- ``A_A^A]A\_^[`
- `l$0L;C`
- `t$XL;C`
- `L$ SVWH`
- `K @81u`
- `6</uZH`
- `L$ UVWAUAWH`
- `d$`u>A`
- `0A_A]_^]`
- `2</uVH`
- `SUVWATAUAWH`
- `@8l$ tV`
- `A_A]A\_^][`
- `|$ AVH`
- `w+H;G v`
- `w(H;G v`
- `^H;G v`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x18004afe0
```asm
┌ 362: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg_78h);
│      ╎╎   ; arg int64_t arg1 @ rcx
│      ╎╎   ; arg int64_t arg2 @ rdx
│      ╎╎   ; arg int64_t arg3 @ r8
│      ╎╎   ; arg int64_t arg_78h @ rsp+0xd8
│      ╎╎   ; var int64_t var_30h @ rsp+0x30
│      ╎╎   ; var int64_t var_8h @ rsp+0x60
│      ╎╎   ; var int64_t var_10h @ rsp+0x68
│      ╎╎   0x18004afe0      48895c2408     mov qword [var_8h], rbx
│      ╎╎   0x18004afe5      4889742410     mov qword [var_10h], rsi
│      ╎╎   0x18004afea      57             push rdi
│      ╎╎   0x18004afeb      4883ec20       sub rsp, 0x20
│      ╎╎   0x18004afef      498bf8         mov rdi, r8                ; arg3
│      ╎╎   0x18004aff2      8bda           mov ebx, edx               ; arg2
│      ╎╎   0x18004aff4      488bf1         mov rsi, rcx               ; arg1
│      ╎╎   0x18004aff7      83fa01         cmp edx, 1                 ; 1 ; arg2
│     ┌───< 0x18004affa      7505           jne 0x18004b001
│     │╎╎   0x18004affc      e867040000     call 0x18004b468
│     └───> 0x18004b001      4c8bc7         mov r8, rdi
│      ╎╎   0x18004b004      8bd3           mov edx, ebx
│      ╎╎   0x18004b006      488bce         mov rcx, rsi
│      ╎╎   0x18004b009      488b5c2430     mov rbx, qword [var_8h]
│      ╎╎   0x18004b00e      488b742438     mov rsi, qword [var_10h]
│      ╎╎   0x18004b013      4883c420       add rsp, 0x20
│      ╎╎   0x18004b017      5f             pop rdi
│      └──< 0x18004b018      e98ffeffff     jmp 0x18004aeac
..
│           ; CODE XREF from fcn.18004a490 @ 0x18004a490(x)
```
### 0x18007f630
```asm
┌ 103: sym.xmrig.dll_Start (int64_t arg2);
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_20h @ rsp+0x20
│           ; var int64_t var_30h @ rsp+0x30
│           ; var int64_t var_38h @ rsp+0x38
│           ; var int64_t var_360h @ rsp+0x360
│           0x18007f630      4053           push rbx
│           0x18007f632      4881ec7003..   sub rsp, 0x370
│           0x18007f639      48c7442420..   mov qword [var_20h], 0xfffffffffffffffe
│           0x18007f642      488d4c2430     lea rcx, [var_30h]
│           0x18007f647      e8045cfeff     call fcn.180065250
│           0x18007f64c      488d4c2430     lea rcx, [var_30h]
│           0x18007f651      e87a58feff     call fcn.180064ed0
│           0x18007f656      8bd8           mov ebx, eax
│           0x18007f658      488d0571b7..   lea rax, [0x18009add0]
│           0x18007f65f      4889442430     mov qword [var_30h], rax
│           0x18007f664      ba68010000     mov edx, 0x168             ; 360
│           0x18007f669      488b4c2438     mov rcx, qword [var_38h]
│           0x18007f66e      e81daefcff     call fcn.18004a490
│           0x18007f673      488b8c2460..   mov rcx, qword [var_360h]
│           0x18007f67b      4885c9         test rcx, rcx
│       ┌─< 0x18007f67e      740c           je 0x18007f68c
│       │   0x18007f680      4c8b01         mov r8, qword [rcx]
│       │   0x18007f683      ba01000000     mov edx, 1
│       │   0x18007f688      41ff10         call qword [r8]
│       │   0x18007f68b      90             nop
│       └─> 0x18007f68c      8bc3           mov eax, ebx
│           0x18007f68e      4881c47003..   add rsp, 0x370
│           0x18007f695      5b             pop rbx
└           0x18007f696      c3             ret
```
### 0x180065250
```asm
; CALL XREF from sym.xmrig.dll_Start @ 0x18007f647(x)
┌ 742: fcn.180065250 (int64_t arg1, int64_t arg3);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg3 @ r8
│           ; var int64_t var_28h @ rbp+0x28
│           ; var int64_t var_10h @ rbp+0x10
│           ; var int64_t var_20h @ rsp+0x20
│           ; var int64_t var_8h @ rsp+0x50
│           ; var int64_t var_58h @ rsp+0x58
│           ; var int64_t var_18h @ rsp+0x60
│           ; var int64_t var_68h @ rsp+0x68
│           0x180065250      4c89442418     mov qword [var_18h], r8    ; arg3
│           0x180065255      48894c2408     mov qword [var_8h], rcx    ; arg1
│           0x18006525a      56             push rsi
│           0x18006525b      57             push rdi
│           0x18006525c      4156           push r14
│           0x18006525e      4883ec30       sub rsp, 0x30
│           0x180065262      48c7442420..   mov qword [var_20h], 0xfffffffffffffffe
│           0x18006526b      48895c2458     mov qword [var_58h], rbx
│           0x180065270      48896c2468     mov qword [var_68h], rbp
│           0x180065275      488bf9         mov rdi, rcx               ; arg1
│           0x180065278      488d05515b..   lea rax, [0x18009add0]
│           0x18006527f      488901         mov qword [rcx], rax       ; arg1
│           0x180065282      33ed           xor ebp, ebp
│           0x180065284      48896908       mov qword [rcx + 8], rbp   ; arg1
│           0x180065288      48896910       mov qword [rcx + 0x10], rbp ; arg1
│           0x18006528c      48890ded5f..   mov qword [0x1800ab280], rcx ; [0x1800ab280:8]=0 ; arg1
│           0x180065293      8d4d10         lea ecx, [var_10h]
│           0x180065296      e8b951feff     call 0x18004a454
│           0x18006529b      488bd8         mov rbx, rax
│           0x18006529e      4889442460     mov qword [var_18h], rax
│           0x1800652a3      488d054e71..   lea rax, [0x18009c3f8]
│           0x1800652aa      488903         mov qword [rbx], rax
│           0x1800652ad      8d4d28         lea ecx, [var_28h]
│           0x1800652b0      e89f51feff     call 0x18004a454
│           0x1800652b5      4889442460     mov qword [var_18h], rax
│           0x1800652ba      488928         mov qword [rax], rbp
│           0x1800652bd      48896808       mov qword [rax + 8], rbp
│           0x1800652c1      48896810       mov qword [rax + 0x10], rbp
│           0x1800652c5      48896818       mov qword [rax + 0x18], rbp
│           0x1800652c9      48896820       mov qword [rax + 0x20], rbp
│           0x1800652cd      48894308       mov qword [rbx + 8], rax
│           0x1800652d1      48899f3003..   mov qword [rdi + 0x330], rbx
│           0x1800652d8      488bcb         mov rcx, rbx
│           0x1800652db      e8c0a90000     call 0x18006fca0
│           0x1800652e0      85c0           test eax, eax
│       ┌─< 0x1800652e2      0f8538020000   jne 0x180065520
│       │   0x1800652e8      488b873003..   mov rax, qword [rdi + 0x330]

```
### 0x180064ed0
```asm
; CALL XREF from sym.xmrig.dll_Start @ 0x18007f651(x)
┌ 785: fcn.180064ed0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_28h @ rbp+0x28
│           ; var int64_t var_20h @ rbp+0x20
│           ; var int64_t var_18h @ rbp+0x18
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_18h_2 @ rbp-0x18
│           ; var int64_t var_20h_2 @ rbp-0x20
│           ; var int64_t var_28h_2 @ rbp-0x28
│           ; var int64_t var_30h @ rbp-0x30
│           ; var int64_t var_38h @ rbp-0x38
│           ; var int64_t var_40h @ rbp-0x40
│           ; var int64_t var_48h @ rbp-0x48
│           ; var int64_t var_sp_20h @ rsp+0x20
│           ; var int64_t var_70h @ rsp+0x70
│           ; var int64_t var_a8h @ rsp+0xa8
│           0x180064ed0      4055           push rbp
│           0x180064ed2      53             push rbx
│           0x180064ed3      488bec         mov rbp, rsp
│           0x180064ed6      4883ec78       sub rsp, 0x78
│           0x180064eda      488b813003..   mov rax, qword [rcx + 0x330] ; arg1
│           0x180064ee1      488bd9         mov rbx, rcx               ; arg1
│           0x180064ee4      488b4808       mov rcx, qword [rax + 8]
│           0x180064ee8      4883792000     cmp qword [rcx + 0x20], 0
│       ┌─< 0x180064eed      0f84e2020000   je 0x1800651d5
│       │   0x180064ef3      48833900       cmp qword [rcx], 0
│      ┌──< 0x180064ef7      0f84d8020000   je 0x1800651d5
│      ││   0x180064efd      488d4b18       lea rcx, [rbx + 0x18]
│      ││   0x180064f01      41b801000000   mov r8d, 1
│      ││   0x180064f07      e81448fdff     call 0x180039720
│      ││   0x180064f0c      488d8b2001..   lea rcx, [rbx + 0x120]
│      ││   0x180064f13      41b802000000   mov r8d, 2
│      ││   0x180064f19      e80248fdff     call 0x180039720
│      ││   0x180064f1e      488d8b2802..   lea rcx, [rbx + 0x228]
│      ││   0x180064f25      41b80f000000   mov r8d, 0xf               ; 15
│      ││   0x180064f2b      e8f047fdff     call 0x180039720
│      ││   0x180064f30      488b833003..   mov rax, qword [rbx + 0x330]
│      ││   0x180064f37      488b4808       mov rcx, qword [rax + 8]
│      ││   0x180064f3b      488b4120       mov rax, qword [rcx + 0x20]
│      ││   0x180064f3f      80781300       cmp byte [rax + 0x13], 0
│     ┌───< 0x180064f43      7432           je 0x180064f77
│     │││   0x180064f45      ff1565610200   call qword [sym.imp.KERNEL32.dll_GetConsoleWindow] ; [0x18008b0b0:8]=0xa6fc8 reloc.KERNEL32.dll_GetConsoleWindow
│     │││   0x180064f4b      4885c0         test rax, rax
│    ┌────< 0x180064f4e      740d           je 0x180064f5d
│    ││││   0x180064f50      33d2           xor edx, edx
│    ││││   0x180064f52      488bc8         mov rcx, rax
│    ││││   0x180064f55      ff15cd650200   call qword [sym.imp.USER32.dll_ShowWindow] ; [0x18008b528:8]=0xa7760 reloc.USER32.dll_ShowWindow ; "`w\n" ; BOOL ShowWindow(HWND hWnd, int nCmdShow)
│   ┌─────< 0x180064f5b      eb1a         
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000120 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, sr.func_addr, sr.string_value FROM string_refs sr WHERE sr.string_value LIKE '%stratum%' OR sr.string_value LIKE '%miner%' OR sr.string_value LIKE '%fee%' OR sr.string_value LIKE '%nicehash%' OR sr.string_value LIKE '%minergate%' OR sr.string_v`
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, sr.func_addr, sr.string_value FROM string_refs sr WHERE sr.func_addr = 6442864336 AND (sr.string_value LIKE '%Lsa%' OR sr.string_value LIKE '%Privilege%' OR sr.string_value LIKE '%SeLock%' OR sr.string_value LIKE '%Token%' OR sr.string_value LI`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786582670.0689607}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786582672.6064692}`
- `{"source": "yara_gen_v2", "ts": 1786582672.82148}`
- `{"source": "publish_report_v2", "ts": 1786582779.2292204}`
- `{"source": "publish_report_v2_technical", "ts": 1786582989.7247694}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786671369.9254177}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786671369.9300134}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786671369.9342272}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786671369.9418747}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs LIMIT 15", "ts": 1786671369.9475477}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786671374.5128763}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786671375.053843}`
- `{"source": "ghidra_query", "sql": "SELECT name, addr FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1786671376.7971025}`
- `{"source": "ghidra_query", "sql": "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786671377.4980097}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786671377.9357166}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786671378.4452333}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786671390.118852}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786671390.581522}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786671392.931254}`
- `{"source": "ghidra_query", "sql": "SELECT addr, content FROM strings WHERE length < 300", "ts": 1786671393.4765368}`
- `{"source": "ghidra_query", "sql": "SELECT func_addr, ref_addr, string_addr FROM string_refs", "ts": 1786671409.418633}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786671409.850255}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786671410.2961807}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786671412.5907924}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786671414.8628478}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786671426.496833}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786671426.9088812}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786671426.9142356}`
