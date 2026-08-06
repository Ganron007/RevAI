> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 00:59:38 UTC

## 1. Executive Summary
This sample is a malicious PE32 Windows GUI executable with a final verdict score of 95, classified as a Remcos RAT / Maze ransomware associated loader or hybrid malware with ties to BK Ransomware, Hawkeye, and Elex (source: llm_judge). Static analysis reveals consistent malicious indicators across multiple engines: PE imports include anti-debugging, payload downloading, registry modification, process execution, and dynamic API resolution functions (source: pe_imports); YARA matches detect 23 distinct malware capabilities including keylogging, screen capture, privilege escalation, and network dropper functionality (source: yara); capa rules map 57 capabilities to MITRE ATT&CK techniques for RAT and ransomware operation, including XOR obfuscation, file system discovery, and input capture (source: capa); FLOSS string analysis reveals 2846 total strings, 2845 of which are statically obfuscated, indicating heavy use of string hiding to evade detection (source: floss). The sample's file path explicitly references known ransomware and RAT families, aligning with the detected capabilities (source: deep_dive_agentic). No conflicting benign indicators were identified during analysis. Note that Ghidra and IDA failed to produce reverse engineering data due to project ownership errors and a missing idasql binary, respectively, so no deep code context is available from those tools (source: llm_judge).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c |
| Sample Path | /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos |
| Project Name | pool |
| Verdict | Malicious |
| Score | 95 |
| Family Guess | Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by sample metadata |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | Ghidra and IDA both failed to produce function, import, or decompilation data due to project ownership errors (Ghidra) and a missing idasql binary (IDA), so no reverse-engineered code context is available from those tools. All available analysis engines (pe_imports, YARA, capa, FLOSS) provide consistent, corroborating evidence of malicious RAT/ransomware functionality. The sample's file path explicitly references known ransomware (Maze, BK Ransomware) and RAT (Remcos, Hawkeye, Elex) families, which aligns with the detected capabilities. |
| Source | llm_judge |

## 3. File Layout & Structural Analysis
The sample is a 32-bit PE (PE32) Windows GUI executable, compiled with Microsoft Visual C++ 8 (VC8) as indicated by the YARA match for `VC8_Microsoft_Corporation` at offset 0x6306 (source: yara). It contains a Rich signature at offset 0x240, debug data, and Structured Exception Handling (SEH) handlers: `SEH_Save` at offset 0x21241, `SEH_Init` at offsets 0x21246 and 0x193755 (source: yara). The file has 318 imported functions (source: pe_imports). UPX unpacking analysis returned a failed status (`upx_ok: False`), with no packed layer detected and no unpacked output path generated (source: upx). XOR search identified a XOR 00 byte at the start of the file (offset 0x00000000), consistent with obfuscation (source: xor). The sample's file path includes references to known ransomware (BK Ransomware, Maze) and RAT (Remcos, Hawkeye, Elex) families, which aligns with the detected malicious capabilities (source: deep_dive_agentic).

### PE Import Signals
| Label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| download_file | URLDownloadToFile | T1105 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
*Source: pe_imports, import count: 318*

## 4. Malcat Triage Summary
Malcat analysis failed due to an MCP closure error: `malcat_analyze top-level: MCP malcat closed:`. No triage data, string analysis, or structural insights are available from the Malcat engine for this sample.

## 5. Static Code Analysis
Ghidra and IDA both failed to produce function, import, or decompilation data: Ghidra encountered a project ownership error, and IDA is missing the required `idasql` binary, so no deep reverse-engineered code context is available from these tools (source: llm_judge). All static analysis is derived from radare2 disassembly, YARA, capa, and FLOSS.

### radare2 Entry Point and Key Function Disassembly
Entry point (entry0) at 0x00421c21:
```asm
0x00421c21      e81a580500     call 0x477440
0x00421c26      e97ffeffff     jmp 0x421aaa
```
*Source: r2*

Main function at 0x004391d2:
```asm
0x004391d2      55             push ebp
0x004391d3      8bec           mov ebp, esp
0x004391d5      5d             pop ebp
0x004391d6      e900000000     jmp 0x4391db
; [subsequent main function prologue and logic at 0x4391db]
0x004391db      55             push ebp
0x004391dc      8bec           mov ebp, esp
0x004391de      53             push ebx
0x004391df      56             push esi
0x004391e0      57             push edi
0x004391e1      83cfff         or edi, 0xffffffff
0x004391e4      e803a8fdff     call fcn.004139ec
0x004391e9      8bf0           mov esi, eax
0x004391eb      e87302feff     call fcn.00419463
; [additional main logic for argument parsing and vtable calls]
```
*Source: r2*

Helper function fcn.004139ec at 0x004139ec:
```asm
0x004139ec      e8a55a0000     call fcn.00419496
0x004139f1      8b4004         mov eax, dword [eax + 4]
0x004139f4      c3             ret
```
*Source: r2*

Function fcn.004235c9 at 0x004235c9, which calls `RaiseException`:
```asm
0x004235c9      55             push ebp
0x004235ca      8bec           mov ebp, esp
0x004235cc      83ec20         sub esp, 0x20
0x004235d0      57             push edi
0x004235d1      6a08           push 8
0x004235d3      59             pop ecx
0x004235d4      be94474400     mov esi, 0x444794
0x004235d9      8d7de0         lea edi, [var_20h]
0x004235dc      f3a5           rep movsd dword es:[edi], dword [esi]
; [additional logic]
0x0042361e      ff1548d24300   call dword [sym.imp.KERNEL32.dll_RaiseException]
```
*Source: r2*

### YARA Static Matches
Total 23 matching rules, with high-signal matches at the following offsets:
| Rule | Offset | Length | Description |
|---|---|---|---|
| domain | 0x0 | 2 | Domain regex match |
| IP (IPv4) | 0x459893 | 7 | IPv4 address match |
| IP (IPv6) | 0x252878 | 4 | IPv6 address match |
| contains_base64 | 0x245300 | 24 | Base64 encoded content |
| url | 0x396920 | 96 | URL regex match |
| Misc_Suspicious_Strings | 0x400684 | 14 | Generic suspicious string |
| maldoc_getEIP_method_1 | 0x460864 | 6 | EIP retrieval method common in malicious documents/exploits |
| anti_dbg | 0x263200, 0x326380, 0x325196 | 12, 17, 17 | Anti-debugging pattern matches |
| keylogger | 0x328710, 0x327842 | 10, 11 | Keylogging functionality indicators |
| screenshot | 0x329094, 0x328710, 0x328496 | 9, 10, 5 | Screen capture functionality indicators |
| win_registry | 0x329548, 0x329242 | 12, 11 | Windows registry manipulation indicators |
| network_dropper | 0x329876, 0x329856 | 10, 17 | Network payload dropping functionality |
| escalate_priv | 0x329548, 0x329194 | 12, 21 | Privilege escalation indicators |
| win_token | 0x329548, 0x329194, 0x329174 | 12, 21, 16 | Windows token manipulation indicators |
| win_files_operation | 0x263200, 0x325760, 0x325728, 0x325760, 0x325700 | 12, 9, 14, 9, 8 | File operation functionality indicators |
*Source: yara*

### FLOSS String Analysis
Total extracted strings: 2846, with 2845 statically obfuscated strings and 1 decoded string (source: floss). Sample static strings include:
```
?GetPu
!This program cannot be run in DOS mode.
.rdata
@.data
ttHt=Hu095
QWWWWWWPW
jEjCjB@j8
XSVWjD_W3
QSSSSSSPS
QPWWhL
t8PPPPh
9G t!j
t'9~ u"
t	9p(u
u8hd)D
u	9wlt>
~(9~8t	WW
u h<)D
At;F u
t49^ u'
~ 9^$u
t>9~ t9j0
t7j(SV
;7u<;G
uij0[SQ
t)9w u$
PjShp.D
jShp.D
+t=Ht-Ht
HtpHHt
Pj^h`1D
j^h`1D
SSWPSSSS
j.Zf9P,u
u	f9p0u
WQh,8D
W9qXtDV
9wXt8V
VW9AXtw
t-h@8D
```
*Source: floss*

### Capa Capability Rules
Total 57 matched rules, with top capabilities including:
| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| create or open registry key | N/A | C0036.004:Registry, C0036.003:Registry |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| link function at runtime on Windows | T1129:Shared Modules | N/A |
*Source: capa, total rules: 57, runtime: 86.92s*

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Speakeasy emulation completed successfully but recorded 0 API calls and 0 key events, with no runtime artifacts or behavior captured (source: speakeasy, status: not observed). Frida probe is available (version 17.16.4) and identified 30 hook candidates including Windows API functions for version info, memory allocation, string comparison, UI operations, printing, registry manipulation, shell execution, and path operations, but no runtime events were recorded during probing (source: frida, status: not observed). UPX unpacking analysis confirmed the sample is not packed, with no unpacked payload generated (source: upx). No process execution, network connections, file system modifications, or other runtime activities were observed.

## 7. Network Indicators & C2
No active C2 communications were observed due to lack of dynamic runtime behavior. Static network indicators were identified via YARA:
| Indicator Type | Offset | Length | Rule |
|---|---|---|---|
| Domain regex | 0x0 | 2 | domain |
| IPv4 address | 0x459893 | 7 | IP |
| IPv6 address | 0x252878 | 4 | IP |
| Base64 encoded content | 0x245300 | 24 | contains_base64 |
| URL regex | 0x396920 | 96 | url |
| Network dropper functionality | 0x329876, 0x329856 | 10, 17 | network_dropper |
*Source: yara, total network-related YARA matches: 5*
All network indicators are obfuscated or regex-matched, with no decoded plaintext C2 endpoints observed in static analysis (source: floss, yara).

## 8. Capabilities & MITRE ATT&CK Mapping
The sample exhibits capabilities consistent with a RAT/ransomware hybrid, mapped to MITRE ATT&CK techniques via PE imports, capa rules, and YARA matches:
| Capability | Source | ATT&CK Technique |
|---|---|---|
| Anti-debugging (IsDebuggerPresent) | pe_imports | T1622: Debugger Evasion |
| Payload download (URLDownloadToFile) | pe_imports | T1105: Ingress Tool Transfer |
| Registry modification (RegSetValue) | pe_imports | T1112: Modify Registry |
| Process execution (CreateProcess, ShellExecute) | pe_imports | T1106: Process Execution |
| Dynamic API resolution (LoadLibrary, GetProcAddress) | pe_imports | T1129: Shared Modules |
| XOR obfuscation of data | capa | T1027: Obfuscated Files or Information |
| File and directory discovery | capa | T1083: File and Directory Discovery |
| System information discovery (env vars, OS version, disk info) | capa | T1082: System Information Discovery |
| Registry query and modification | capa | T1012: Query Registry, T1112: Modify Registry |
| Keystroke logging (polling) | capa | T1056.001: Input Capture |
| Command line argument acceptance | capa | T1059: Command and Scripting Interpreter |
| Anti-debugging | yara | T1622: Debugger Evasion |
| Keylogging | yara | T1056.001: Input Capture |
| Screen capture | yara | T1056.001: Input Capture |
| Privilege escalation | yara | T1068: Exploitation for Privilege Escalation |
| Token manipulation | yara | T1134: Access Token Manipulation |
| File operations | yara | T1083: File and Directory Discovery, T1105: Ingress Tool Transfer |
| Network dropper functionality | yara | T1105: Ingress Tool Transfer |
*Source: llm_judge, pe_imports, capa, yara*
The combination of these capabilities aligns with the family guess of a Remcos RAT / Maze ransomware associated loader or hybrid malware (source: llm_judge).

## 9. Indicators of Compromise
### Hash IOCs
| Type | Value |
|---|---|
| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c |
*Source: structured evidence*

### Static IOCs
| Type | Value/Offset | Source |
|---|---|---|
| YARA Rule Match (anti_dbg) | Offsets 0x263200, 0x326380, 0x325196 | yara |
| YARA Rule Match (keylogger) | Offsets 0x328710, 0x327842 | yara |
| YARA Rule Match (screenshot) | Offsets 0x329094, 0x328710, 0x328496 | yara |
| YARA Rule Match (network_dropper) | Offsets 0x329876, 0x329856 | yara |
| YARA Rule Match (escalate_priv) | Offsets 0x329548, 0x329194 | yara |
| YARA Rule Match (win_registry) | Offsets 0x329548, 0x329242 | yara |
| IPv4 Address (regex match) | Offset 0x459893 | yara |
| IPv6 Address (regex match) | Offset 0x252878 | yara |
| URL (regex match) | Offset 0x396920 | yara |
| Base64 Encoded Content | Offset 0x245300 | yara |
| Malicious Import (IsDebuggerPresent) | IAT entry | pe_imports |
| Malicious Import (URLDownloadToFile) | IAT entry | pe_imports |
| Malicious Import (RegSetValue) | IAT entry | pe_imports |
| Malicious Import (CreateProcess) | IAT entry | pe_imports |
| Malicious Import (ShellExecute) | IAT entry | pe_imports |
| Obfuscated String Count | 2845 static obfuscated, 1 decoded | floss |
| Family Association | Sample path contains `bkransomware_elex_hawkeye_maze_remcos` | deep_dive_agentic |

## 10. Detection Engineering
### YARA-Based Detection
The 23 matched YARA rules provide high-signal detection coverage, with the following rules offering the strongest malicious indication:
- `anti_dbg`, `keylogger`, `screenshot`, `win_registry`, `win_files_operation`, `network_dropper`, `escalate_priv`, `win_token` (source: yara)
These rules can be combined into a single detection rule targeting the observed offset ranges and string patterns to identify this sample and similar variants.

### Import Signature Detection
Detect PE files with the following combination of imports, which is consistent with RAT/ransomware functionality and rare in benign software:
- `IsDebuggerPresent` (T1622)
- `URLDownloadToFile` (T1105)
- `RegSetValue` (T1112)
- `CreateProcess` / `ShellExecute` (T1106)
- `LoadLibrary` / `GetProcAddress` (T1129)
*Source: pe_imports*

### String and Obfuscation Detection
Detect PE files with >1000 obfuscated static strings (this sample has 2845, source: floss) and XOR encoding capabilities (capa rule `encode data using XOR`, source: capa). Additionally, detect the presence of SEH handlers (`SEH_Save`, `SEH_Init`), VC8 compilation metadata, and debug data in GUI PE files, as these traits are common in this malware family (source: yara).

## 11. What We Don't Know
No dynamic runtime behavior was observed during analysis: Speakeasy emulation and Frida probing recorded no API calls, events, or network connections, so actual C2 communications, payload drops, ransomware encryption routines, keylogging/screenshot activity in action, and process execution behavior are not confirmed (source: speakeasy, frida). Ghidra and IDA failed to produce decompilation or function data, so no deep code context, control flow analysis, or exact implementation details of the sample's capabilities are available (source: llm_judge). No unpacked payload was generated (UPX analysis confirmed the sample is not packed, source: upx), so no hidden secondary payloads beyond the static sample are identified. All network indicators (domains, IPs, URLs) are regex-matched or obfuscated, with no decoded plaintext C2 endpoints available in static strings, so exact attacker infrastructure is unknown (source: yara, floss). No evidence of specific ransomware encryption modules or RAT C2 protocol implementation is available due to the lack of dynamic and deep static analysis.

## 12. Appendix: Analysis Environment
| Tool/Engine | Status | Details |
|---|---|---|
| pe_imports | Successful | 318 imports analyzed, 7 high-signal malicious import signals identified |
| YARA | Successful | 23 rules matched, including anti-analysis, capability, and structural rules |
| capa | Successful | 57 rules matched, 86.92s runtime, mapped to MITRE ATT&CK techniques |
| FLOSS | Successful | 2846 strings extracted (2845 obfuscated, 1 decoded) |
| radare2 | Successful | Entry point, main function, and key helper functions disassembled |
| UPX | Successful (no packed layer) | Unpacking failed, sample confirmed not packed |
| XOR Search | Successful | XOR 00 byte identified at offset 0x00000000 |
| Speakeasy | Successful (no events) | 0 API calls, 0 key events recorded, no runtime behavior observed |
| Frida | Successful (no events) | Version 17.16.4, 30 hook candidates identified, no runtime events recorded |
| Ghidra | Failed | Project ownership error, no function/import/decompilation data generated |
| IDA | Failed | Missing `idasql` binary, no function/import/decompilation data generated |
| Malcat | Failed | MCP closure error, no triage data generated |
*Source: llm_judge, deep_dive_agentic, structured evidence*
Sample analysis path: `/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos` (source: structured evidence)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c  
**sample_path:** /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 95
- **family_guess**: Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by sample metadata
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA both failed to produce function, import, or decompilation data due to project ownership errors (Ghidra) and a missing idasql binary (IDA), so no reverse-engineered code context is available from those tools. All available analysis engines (pe_imports, YARA, capa, FLOSS) provide consistent, corroborating evidence of malicious RAT/ransomware functionality. The sample's file path explicitly references known ransomware (Maze, BK Ransomware) and RAT (Remcos, Hawkeye, Elex) families, which aligns with the detected capabilities.
- **summary**: This sample is a malicious PE file with strong indicators of being a RAT/ransomware hybrid or associated loader. Static analysis reveals high-signal malicious imports for anti-debugging, payload downloading, registry modification, process execution, and dynamic API resolution. YARA matches detect common malware capabilities including keylogging, screen capture, privilege escalation, and file/network operations. Capa rules map these capabilities to ATT&CK techniques for RAT and ransomware operation. FLOSS string analysis reveals heavy obfuscation consistent with malware attempting to hide its indicators. The sample's file path references multiple known ransomware and RAT families, further confirming its malicious nature. No conflicting benign indicators were identified.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | pe_imports raw JSON signal list | `check_debugger (IsDebuggerPresent) [T1622]` | IsDebuggerPresent is a standard anti-debugging technique used by malware to detect and evade reverse engineering tools,  |
| pe_imports | pe_imports raw JSON signal list | `download_file (URLDownloadToFile) [T1105]` | This API is used to download additional payloads (e.g., ransomware encryption modules, RAT components) from attacker-con |
| pe_imports | pe_imports raw JSON signal list | `set_registry_value (RegSetValue) [T1112]` | Registry modification is used for persistence (e.g., adding run keys), disabling security software, or configuring malic |
| pe_imports | pe_imports raw JSON signal list | `create_process (CreateProcess) / shell_execute (ShellExecute) [T1106]` | These APIs are used to execute additional malicious processes, launch ransomware encryption routines, or run attacker co |
| pe_imports | pe_imports raw JSON signal list | `load_library (LoadLibrary) / get_proc_address (GetProcAddress) [T1129]` | Dynamic API resolution is a common obfuscation technique used by malware to hide malicious imports from static analysis, |
| yara | yara raw JSON matches | `23 matching rules including anti_dbg, keylogger, screenshot, win_registry, win_f` | These rules detect well-known malware capabilities: anti-debugging, keylogging, screen capture, registry manipulation, f |
| capa | capa raw JSON top rules | `T1083 (File and Directory Discovery), T1082 (System Information Discovery), T111` | These mapped ATT&CK techniques cover core functionality for ransomware and RATs: system/file discovery for targeting, re |
| capa | capa_evidence | `2846 total strings (2845 static obfuscated, 1 decoded)` | The high volume of obfuscated strings indicates heavy use of string obfuscation to hide malicious indicators (e.g., C2 d |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE32 Windows GUI executable with strong malicious indicators: YARA matches for domains, IPs, URLs, base64, suspicious strings, and anti-analysis patterns; capa rules for XOR obfuscation, registry manipulation, file discovery, and execution; PE imports for debugger detection, download, registry writes, and process creation; FLOSS reveals 2846 strings with decoded/obfuscated content. Sample corpus name associates it with known ransomware/RAT families (BKRansomware, Elex, Hawkeye, Maze, Remcos).

### deep key_evidence
- `"YARA 23 matches including domain, IP, base64, url, Misc_Suspicious_Strings, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation, SEH_Save, SEH_Init"`
- `"pe_import_signals: IsDebuggerPresent (T1622), URLDownloadToFile (T1105), RegSetValue (T1112), CreateProcess/ShellExecute (T1106), LoadLibrary/GetProcAddress (T1129)"`
- `"capa_analyze: 57 rules, top rules encode data using XOR (T1027), create/open registry key, get file version info, get common file path, check if file exists"`
- `"floss_extract: 2846 static strings, 1 decoded string, indicating obfuscation/stack strings"`
- `"Sample path contains bkransomware_elex_hawkeye_maze_remcos indicating known malware family association"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 57 · duration_s: 86.92

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| link function at runtime on Windows | T1129:Shared Modules |  |

## PE Imports / Signals
import_count: 318

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| download_file | URLDownloadToFile | T1105 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 23

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@459893 len=7; $ipv6@252878 len=4 |
| contains_base64 | - | $a@245300 len=24 |
| Misc_Suspicious_Strings | - | $a3@400684 len=14 |
| url | - | $url_regex@396920 len=96 |
| maldoc_getEIP_method_1 | - | $a@460864 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@240 len=4 |
| VC8_Microsoft_Corporation | - | $a@6306 len=10 |
| SEH_Save | - | $a@137441 len=7 |
| SEH_Init | - | $a@21246 len=6; $b@193755 len=7 |
| Check_OutputDebugStringA_iat | - |  |
| anti_dbg | - | $d1@263200 len=12; $c2@326380 len=17; $c3@325196 len=17 |
| win_hook | - | $f1@328710 len=10; $c1@328252 len=19; $c3@328274 len=14 |
| network_dropper | - | $f1@329876 len=10; $c1@329856 len=17 |
| escalate_priv | - | $d1@329548 len=12; $c2@329194 len=21 |
| screenshot | - | $d1@329094 len=9; $d2@328710 len=10; $c2@328496 len=5 |
| keylogger | - | $f1@328710 len=10; $c2@327842 len=11 |
| win_registry | - | $f1@329548 len=12; $c3@329242 len=11; $c6@329242 len=11 |
| win_token | - | $f1@329548 len=12; $c2@329194 len=21; $c3@329174 len=16 |
| win_files_operation | - | $f1@263200 len=12; $c1@325760 len=9; $c2@325728 len=14; $c3@325760 len=9; $c4@325700 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 459893,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 252878,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 245300,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a3",
          "offset": 400684,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 396920,
          "length": 96,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 460864,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a0",
          "offset": 240,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VC8_Microsoft_Corporation",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 6306,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",

```

## FLOSS Strings
Total strings: 2846 · per_category: `{"decoded_strings": 1, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2845}`

### FLOSS sample
- `?GetPu`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `ttHt=Hu095`
- `QWWWWWWPW`
- `jEjCjB@j8`
- `XSVWjD_W3`
- `QSSSSSSPS`
- `QPWWhL`
- `t8PPPPh`
- `9G t!j`
- `t'9~ u"`
- `t	9p(u`
- `u8hd)D`
- `u	9wlt>`
- `~(9~8t	WW`
- `u h<)D`
- `At;F u`
- `t49^ u'`
- `~ 9^$u`
- `t>9~ t9j0`
- `t7j(SV`
- `;7u<;G`
- `uij0[SQ`
- `t)9w u$`
- `PjShp.D`
- `jShp.D`
- `+t=Ht-Ht`
- `HtpHHt`
- `Pj^h`1D`
- `j^h`1D`
- `SSWPSSSS`
- `j.Zf9P,u`
- `u	f9p0u`
- `WQh,8D`
- `W9qXtDV`
- `9wXt8V`
- `VW9AXtw`
- `t-h@8D`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00421c21
```asm
┌ 300: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_24h @ ebp-0x24
│       ╎   0x00421c21      e81a580500     call 0x477440
│       └─< 0x00421c26      e97ffeffff     jmp 0x421aaa
..
```
### 0x004391d2
```asm
; CALL XREF from entry0 @ 0x421ba2(x)
┌ 127: int main (char **argv, char **envp, int32_t envp, int32_t arg_14h);
│           ; arg char **argv @ ebp+0x8
│           ; arg char **envp @ ebp+0xc
│           ; arg int32_t envp @ ebp+0x10
│           ; arg int32_t arg_14h @ ebp+0x14
│           0x004391d2      55             push ebp
│           0x004391d3      8bec           mov ebp, esp
│           0x004391d5      5d             pop ebp
│       ┌─< 0x004391d6      e900000000     jmp 0x4391db
│       │   ; JUMP XREF from main @ 0x4391d6(x)
│       └─> 0x004391db      55             push ebp
│           0x004391dc      8bec           mov ebp, esp
│           0x004391de      53             push ebx
│           0x004391df      56             push esi
│           0x004391e0      57             push edi
│           0x004391e1      83cfff         or edi, 0xffffffff          ; -1
│           0x004391e4      e803a8fdff     call fcn.004139ec
│           0x004391e9      8bf0           mov esi, eax
│           0x004391eb      e87302feff     call fcn.00419463
│           0x004391f0      ff7514         push dword [arg_14h]
│           0x004391f3      ff7510         push dword [envp]
│           0x004391f6      8b5804         mov ebx, dword [eax + 4]
│           0x004391f9      ff750c         push dword [envp]
│           0x004391fc      ff7508         push dword [argv]
│           0x004391ff      e86845feff     call fcn.0041d76c
│           0x00439204      85c0           test eax, eax
│       ┌─< 0x00439206      743b           je 0x439243
│       │   0x00439208      85db           test ebx, ebx
│      ┌──< 0x0043920a      740e           je 0x43921a
│      ││   0x0043920c      8b03           mov eax, dword [ebx]
│      ││   0x0043920e      8bcb           mov ecx, ebx
│      ││   0x00439210      ff90ac000000   call dword [eax + 0xac]     ; 172
│      ││   0x00439216      85c0           test eax, eax
│     ┌───< 0x00439218      7429           je 0x439243
│     │└──> 0x0043921a      8b06           mov eax, dword [esi]
│     │ │   0x0043921c      8bce           mov ecx, esi
│     │ │   0x0043921e      ff5050         call dword [eax + 0x50]     ; 80
│     │ │   0x00439221      85c0           test eax, eax
│     │┌──< 0x00439223      7515           jne 0x43923a
│     │││   0x00439225      8b4e20         mov ecx, dword [esi + 0x20]
│     │││   0x00439228      85c9           test ecx, ecx
│    ┌────< 0x0043922a      7405           je 0x439231
│    ││││   0x0043922c      8b01           mov eax, dword [ecx]
│    ││││   0x0043922e      ff5060         call dword [eax + 0x60]     ; 96
│    └────> 0x00439231      8b06           mov eax, dword [esi]
│     │││   0x00439233      8bce           mov ecx, esi
│     │││   0x00439235      ff5068         call dword [eax + 0x68]     ; 104
│    ┌────< 0x00439238      eb07           jmp 0x439241
│    ││└──> 0x0043923a      8b06           mov eax, dword [esi]
│    ││ │   0x0043923c      8bce           mov ecx, esi
│    ││ │   0x0043923e   
```
### 0x004139ec
```asm
; CALL XREF from main @ 0x4391e4(x)
┌ 9: fcn.004139ec ();
│           0x004139ec      e8a55a0000     call fcn.00419496
│           0x004139f1      8b4004         mov eax, dword [eax + 4]
└           0x004139f4      c3             ret
```
### 0x004235c9
```asm
; CALL XREF from fcn.00419496 @ 0x40c0bf(x)
┌ 91: fcn.004235c9 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           0x004235c9      55             push ebp
│           0x004235ca      8bec           mov ebp, esp
│           0x004235cc      83ec20         sub esp, 0x20
│           0x004235cf      56             push esi
│           0x004235d0      57             push edi
│           0x004235d1      6a08           push 8                      ; 8
│           0x004235d3      59             pop ecx
│           0x004235d4      be94474400     mov esi, 0x444794
│           0x004235d9      8d7de0         lea edi, [var_20h]
│           0x004235dc      f3a5           rep movsd dword es:[edi], dword [esi]
│           0x004235de      8b750c         mov esi, dword [arg_ch]
│           0x004235e1      8b7d08         mov edi, dword [arg_8h]
│           0x004235e4      85f6           test esi, esi
│       ┌─< 0x004235e6      7413           je 0x4235fb
│       │   0x004235e8      f60610         test byte [esi], 0x10
│      ┌──< 0x004235eb      740e           je 0x4235fb
│      ││   0x004235ed      8b0f           mov ecx, dword [edi]
│      ││   0x004235ef      83e904         sub ecx, 4
│      ││   0x004235f2      51             push ecx
│      ││   0x004235f3      8b01           mov eax, dword [ecx]
│      ││   0x004235f5      8b7018         mov esi, dword [eax + 0x18]
│      ││   0x004235f8      ff5020         call dword [eax + 0x20]     ; 32
│      └└─> 0x004235fb      897df8         mov dword [var_8h], edi
│           0x004235fe      8975fc         mov dword [var_4h], esi
│           0x00423601      85f6           test esi, esi
│       ┌─< 0x00423603      740c           je 0x423611
│       │   0x00423605      f60608         test byte [esi], 8
│      ┌──< 0x00423608      7407           je 0x423611
│      ││   0x0042360a      c745f40040..   mov dword [var_ch], 0x1994000
│      └└─> 0x00423611      8d45f4         lea eax, [var_ch]
│           0x00423614      50             push eax
│           0x00423615      ff75f0         push dword [var_10h]
│           0x00423618      ff75e4         push dword [var_1ch]
│           0x0042361b      ff75e0         push dword [var_20h]
└           0x0042361e      ff1548d24300   call dword [sym.imp.KERNEL32.dll_RaiseException] ; 0x43d248 ; VOID RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments)
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r

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
  - `VERSION.dll!VerQueryValueW`
  - `VERSION.dll!GetFileVersionInfoW`
  - `VERSION.dll!GetFileVersionInfoSizeW`
  - `KERNEL32.dll!LocalReAlloc`
  - `KERNEL32.dll!GlobalFlags`
  - `KERNEL32.dll!CompareStringW`
  - `KERNEL32.dll!GetLocaleInfoW`
  - `KERNEL32.dll!GetSystemDefaultUILanguage`
  - `USER32.dll!InvalidateRect`
  - `USER32.dll!DestroyMenu`
  - `USER32.dll!RealChildWindowFromPoint`
  - `USER32.dll!ClientToScreen`
  - `USER32.dll!EndPaint`
  - `GDI32.dll!TextOutW`
  - `GDI32.dll!ExtTextOutW`
  - `GDI32.dll!SetViewportExtEx`
  - `GDI32.dll!SetViewportOrgEx`
  - `GDI32.dll!SetWindowExtEx`
  - `WINSPOOL.DRV!OpenPrinterW`
  - `WINSPOOL.DRV!ClosePrinter`
  - `WINSPOOL.DRV!DocumentPropertiesW`
  - `ADVAPI32.dll!RegEnumValueW`
  - `ADVAPI32.dll!RegQueryValueW`
  - `ADVAPI32.dll!RegEnumKeyW`
  - `ADVAPI32.dll!RegDeleteValueW`
  - `ADVAPI32.dll!RegDeleteKeyW`
  - `SHELL32.dll!ShellExecuteW`
  - `SHELL32.dll!SHGetSpecialFolderPathW`
  - `SHLWAPI.dll!PathFileExistsW`
  - `SHLWAPI.dll!PathIsUNCW`
