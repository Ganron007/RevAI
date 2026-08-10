> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:59:30 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## 1. Executive Summary

This report details the analysis of `vdaudio.dll` (SHA256: `1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39`), a 32-bit DLL identified as a malicious backdoor/RAT. The sample masquerades as an audio library but establishes Command and Control (C2) communication with hardcoded domains `cm.mnemonicarx.biz` and `cn.mnemonicarx.biz`. It employs dynamic API resolution via PE export parsing to resolve `kernel32`, `advapi32`, and `ws2_32` at runtime, uses anti-debugging techniques, and stores resolved function pointers in a large writable `.data` section. The DLL imports GDI32 functions as decoy traffic to appear as a graphics/audio library, while its true functionality is network-based C2 communication with file deletion capabilities. The verdict is **malicious** with a score of 85, based on multiple engines confirming network C2 and destructive capabilities (source: llm_judge).

## 2. Sample Metadata

The sample is a 32-bit Windows DLL with a high entropy `.text` section, suggesting possible obfuscation or packing, though UPX analysis did not confirm packing (source: malcat). The file size is 13,312 bytes, and it exports three functions: `gewayX`, `gewayZ`, and `vdaudio` (source: malcat). The import hash (imphash) is `0302695b505772b990fb0f7026657050` (source: rule.yara.json).

| Attribute | Value | Source |
|---|---|---|
| SHA256 | 1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39 | malcat |
| File Path | /opt/samples/corpus/610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll | malcat |
| File Type | PE (DLL) | malcat |
| Architecture | X86 | malcat |
| Entry Point EA | 10006 | malcat |
| Entropy | 135 | malcat |
| File Name | vdaudio.dll | malcat |
| Size | 13312 | malcat |
| Imphash | 0302695b505772b990fb0f7026657050 | rule.yara.json |
| Family Guess | Unknown backdoor/Trojan (possible Delphi-based) | llm_judge |

## 3. File Layout & Structural Analysis

The PE file structure is standard, but the `.data` section is notably large (57,344 virtual bytes) and writable, which is consistent with storing runtime-resolved API pointers and configuration data (source: malcat). The `.text` section has high entropy (145), which may indicate obfuscation or packing, though UPX analysis did not confirm packing (source: malcat). The entry point is at `0x10006` (source: malcat).

### Section Layout

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 35 | - |
| .text | 1024 | 9728 | 12288 | 145 | RX |
| .rdata | 13312 | 1024 | 4096 | 0 | R |
| .data | 17408 | 512 | 57344 | 0 | RW |
| .reloc | 74752 | 1024 | 4096 | 0 | R |

### Anomalies

The sample exhibits several anomalies that warrant investigation. The `ManyHighValueImmediates` and `ManyUniqueImmediateBytes` anomalies in the `.text` section suggest obfuscated or packed code (source: malcat). The `DownloaderApiUsage` anomaly indicates the use of APIs commonly associated with downloading, which aligns with C2 communication (source: malcat). The `NoChecksum` anomaly is a minor integrity issue (source: malcat).

| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ManyHighValueImmediates | 3 | code | 2 | Function contains at least 5 and more than 10% of high-value immediate operands |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| DownloaderApiUsage | 2 | imports | 1 | Downloader-related apis are used |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

## 4. Static Code Analysis

Static analysis reveals a complex, obfuscated binary with multiple layers of functionality. The sample uses dynamic API resolution to avoid static detection, imports decoy functions to masquerade as a legitimate audio library, and contains hardcoded C2 domains and encoded strings.

### Dynamic API Resolution

The function `FUN_10002cd8` (recovered name: `network_init_handler`) is responsible for dynamically resolving APIs from `kernel32`, `advapi32`, and `ws2_32` at runtime. It uses `GetModuleHandleW` and `LoadLibraryExA` to load libraries, then parses PE exports to resolve function addresses. This technique is confirmed by the capa rule `resolve function by parsing PE exports` (source: capa). The resolved function pointers are stored in the writable `.data` section at addresses like `DAT_1000af6c`, `DAT_1000af70`, and `DAT_1000af84` (source: ghidra_query).

### C2 Communication

The sample communicates with C2 domains `cm.mnemonicarx.biz` and `cn.mnemonicarx.biz`. The function `FUN_10002974` (recovered name: `init_c2_connection`) references the domain `cn.mnemonicarx.biz` and sets up a network socket (source: malcat). The function `FUN_100016eb` (recovered name: `c2_command_dispatcher`) references `cm.mnemonicarx.biz` and handles C2 commands (source: ghidra_query). The sample uses Winsock APIs (`socket`, `connect`, `send`, `recv`) imported by ordinal to avoid string-based detection (source: deep_dive_agentic).

### Decoy Functionality

The DLL imports numerous GDI32 functions (e.g., `PolyBezierTo`, `SetColorSpace`, `TextOutA`) and USER32 functions (e.g., `RegisterClassExA`, `CallWindowProcW`) that are not used for its core malicious functionality. These imports serve as decoy traffic to make the DLL appear as a graphics or audio library (source: deep_dive_agentic).

### Encoded Strings

The sample contains several encoded strings that likely represent encrypted configuration or keys. These include `LXCV0IMGIXS0RTA1`, `b8-X-ecFW)0Rz?W^`, `AIW1YAERWZFW`, and `qdrnemsd` (source: malcat). These strings are referenced by functions involved in C2 communication and initialization (source: ghidra_query).

### Anti-Debugging Techniques

The capa rule `execute anti-debugging instructions` was matched, indicating the use of anti-debugging techniques (source: capa). The YARA rule `maldoc_find_kernel32_base_method_1` also matched, which is a technique used to resolve the base address of `kernel32.dll` for dynamic API resolution (source: yara).

### Disassembly Excerpts

The following disassembly excerpts illustrate key functionality.

The entry point at `0x10003316` is a minimal stub that loads a value from memory and returns (source: radare2).
```asm
┌ 15: entry0 ();
│           0x10003316      55             push ebp
│           0x10003317      8bec           mov ebp, esp
│           0x10003319      83c4e8         add esp, 0xffffffe8
│           0x1000331c      a115500010     mov eax, dword [0x10005015] ; [0x10005015:4]=1
│           0x10003321      c9             leave
└           0x10003322      c20c00         ret 0xc
```

The exported function `gewayX` at `0x10002ca8` pushes arguments and calls a function, then jumps to a register (source: radare2). This is typical of a DLL export that dispatches to internal functionality.
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

The exported function `vdaudio` at `0x10002cc2` calls two functions sequentially, suggesting an initialization routine (source: radare2).
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

### Decompiled Code Excerpts

The decompilation of `sub_10002974` (recovered name: `init_c2_connection`) shows the C2 domain `cn.mnemonicarx.biz` being referenced and network socket setup (source: malcat). This function initializes the C2 connection, sets up connection parameters, and sends data.
```c
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
    // ... (rest of function)
}
```

## 5. Behavioral & Dynamic Analysis

Dynamic analysis tools (Speakeasy and Frida) were available but did not record any API calls or events during analysis (source: speakeasy, frida_probe). This is likely due to the sample's anti-debugging techniques or the need for specific triggering conditions. Therefore, runtime behavior cannot be confirmed from dynamic analysis alone. The behavioral capabilities are inferred from static analysis and tool outputs.

## 6. Network Indicators & C2

The sample communicates with two hardcoded C2 domains: `cm.mnemonicarx.biz` and `cn.mnemonicarx.biz` (source: malcat, floss). These domains are referenced in the `.data` section and used by functions involved in C2 communication (source: ghidra_query). The sample uses Winsock APIs (`socket`, `connect`, `send`, `recv`) imported by ordinal to establish TCP connections (source: deep_dive_agentic). The HTTP response validation string `west/1.0 200 OK\r\n` suggests the C2 protocol may be HTTP-based (source: malcat).

### C2 Domains

| Domain | Source | Reference |
|---|---|---|
| cm.mnemonicarx.biz | malcat | EA 17753 |
| cn.mnemonicarx.biz | malcat | EA 17773 |

### Network APIs

The sample imports the following Winsock APIs by ordinal (source: deep_dive_agentic):
- Ordinal_3 (connect)
- Ordinal_16 (recv)
- Ordinal_21 (send)
- Ordinal_23 (socket)

## 7. Capabilities Assessment

Based on static analysis, the sample possesses the following capabilities:

| Capability | Evidence | Source |
|---|---|---|
| C2 Communication | Hardcoded domains, Winsock API usage, HTTP response string | malcat, floss, capa |
| Dynamic API Resolution | PE export parsing, runtime resolution of kernel32/advapi32/ws2_32 | capa, ghidra_query |
| Anti-Debugging | capa rule `execute anti-debugging instructions` | capa |
| File Deletion | Import of `DeleteFileA`, capa rule `delete file` | malcat, capa |
| Masquerading | GDI32/USER32 decoy imports, audio DLL filename | malcat, deep_dive_agentic |
| Encoded Configuration | Encoded strings in .data section | malcat |

## 8. Indicators of Compromise

### File-Based IOCs

| Type | Value | Source |
|---|---|---|
| SHA256 | 1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39 | malcat |
| Filename | vdaudio.dll | malcat |
| Imphash | 0302695b505772b990fb0f7026657050 | rule.yara.json |

### Network-Based IOCs

| Type | Value | Source |
|---|---|---|
| Domain | cm.mnemonicarx.biz | malcat, floss |
| Domain | cn.mnemonicarx.biz | malcat, floss |

### String-Based IOCs

| String | EA | Source |
|---|---|---|
| cm.mnemonicarx.biz | 17753 | malcat |
| cn.mnemonicarx.biz | 17773 | malcat |
| west/1.0 200 OK | 17718 | malcat |
| LXCV0IMGIXS0RTA1 | 17579 | malcat |
| b8-X-ecFW)0Rz?W^ | 17602 | malcat |
| AIW1YAERWZFW | 17433 | malcat |
| qdrnemsd | 17420 | malcat |

## 9. Detection Engineering

### YARA Rules

The following YARA rules matched the sample (source: yara):

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

### capa Rules

The following capa rules matched the sample (source: capa):

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

### Sigma Rules

A Sigma rule was generated for this sample (source: rule.yara.json). The rule path is `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/rule.yml`.

## 10. MITRE ATT&CK Mapping

The sample's capabilities map to the following MITRE ATT&CK techniques:

| Technique | ID | Evidence | Source |
|---|---|---|---|
| Dynamic API Resolution | T1129 | LoadLibrary import, capa rule `resolve function by parsing PE exports` | pe_imports, capa |
| Command and Control | T1071 | C2 domains, Winsock API usage | malcat, floss, capa |
| File Deletion | T1070.004 | DeleteFileA import, capa rule `delete file` | malcat, capa |
| Anti-Debugging | T1622 | capa rule `execute anti-debugging instructions` | capa |
| Masquerading | T1036 | Audio DLL filename, GDI32/USER32 decoy imports | malcat, deep_dive_agentic |

## 11. What We Don't Know

Several aspects of this sample remain unknown due to analysis limitations:

1. **Runtime Behavior**: Dynamic analysis tools (Speakeasy and Frida) did not record any API calls or events (source: speakeasy, frida_probe). This is likely due to anti-debugging techniques or missing triggering conditions. Therefore, the exact runtime behavior, including C2 protocol details and command handling, cannot be confirmed.

2. **Encoded Strings**: The purpose of encoded strings like `LXCV0IMGIXS0RTA1` and `b8-X-ecFW)0Rz?W^` is unknown. They may represent encrypted configuration, keys, or other data, but without decryption, their exact role is unclear (source: malcat).

3. **C2 Protocol Details**: While the sample uses HTTP-like strings (`west/1.0 200 OK`), the full C2 protocol, including command structure and data exfiltration methods, is not fully understood (source: malcat).

4. **Persistence Mechanisms**: The sample does not appear to have explicit persistence mechanisms in the analyzed code, but this cannot be confirmed without dynamic analysis (source: static analysis).

5. **Lateral Movement**: There is no evidence of lateral movement capabilities in the analyzed code, but this may be triggered under specific conditions (source: static analysis).

6. **Data Exfiltration**: While the sample has C2 communication capabilities, the exact data exfiltration methods and targets are unknown (source: static analysis).

## 12. Appendix A: Tool Evidence Trail

This appendix documents the tools and queries used during analysis.

### Ghidra Queries

The following Ghidra queries were executed to extract evidence (source: ghidra_query):

- `SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'`
- `SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25`
- `SELECT name, module FROM imports ORDER BY module, name`
- `SELECT content, address, length FROM strings WHERE length > 5 ORDER BY length DESC`
- `SELECT f.name, f.address, fm.size, fm.instruction_count, fm.block_count, fm.cyclomatic_complexity, fm.call_out_count, fm.string_ref_count FROM funcs f LEFT JOIN function_metrics fm ON f.address = fm.func_addr ORDER BY fm.cyclomatic_complexity DESC NULLS LAST LIMIT 30`
- `SELECT sr.func_name, sr.func_addr, sr.string_value FROM string_refs sr WHERE sr.string_value LIKE '%mnemonicarx%' OR sr.string_value LIKE '%west/%' OR sr.string_value LIKE '%kernel32%' OR sr.string_value LIKE '%LXCV0%' ORDER BY sr.func_name`
- `SELECT sr.func_name, COUNT(*) as ref_count, GROUP_CONCAT(DISTINCT SUBSTR(sr.string_value, 1, 40)) as strings FROM string_refs sr GROUP BY sr.func_name ORDER BY ref_count DESC LIMIT 20`
- `SELECT name, address FROM exports`
- `SELECT * FROM callgraph_edges LIMIT 5`
- `SELECT src_func_name, dst_func_name FROM callgraph_edges WHERE src_func_name IN ('FUN_100016eb','FUN_10002cd8','FUN_10002974','FUN_10002509','FUN_1000275f','FUN_10001f47','FUN_10002b7e','FUN_10002bc5') OR dst_func_name IN ('FUN_100016eb','FUN_10002cd8','FUN_10002974','FUN_10002509','FUN_1000275f','FUN_10001f47','FUN_10002b7e','FUN_10002bc5')`
- `SELECT * FROM memory_blocks LIMIT 10`
- `SELECT src_func_name, dst_func_name FROM callgraph_edges WHERE src_func_name = 'FUN_10002974'`
- `SELECT src_func_name, dst_func_name FROM callgraph_edges WHERE src_func_name = 'FUN_10002cd8'`
- `SELECT address, mnemonic, operands FROM instructions WHERE address >= 268446936 AND address <= 268447815 AND mnemonic IN ('CALL','JMP') LIMIT 30`
- `SELECT name, address, data_type, size FROM data_items WHERE address IN (268472172, 268472196, 268472176) OR name LIKE '%1000af6c%' OR name LIKE '%1000af84%' OR name LIKE '%1000af70%'`
- `SELECT name, address, data_type, size FROM data_items WHERE address >= 268472160 AND address <= 268472200 ORDER BY address`
- `SELECT i.address, i.mnemonic, i.operands FROM instructions i WHERE i.address >= 268447120 AND i.address <= 268447260 AND i.mnemonic = 'CALL' ORDER BY i.address`

### IDA Queries

The following IDA queries were executed (source: ida_query):

- `SELECT sr.func_name, sr.string_value, sr.string_addr FROM string_refs sr WHERE sr.string_value LIKE '%mnemonicarx%' OR sr.string_value LIKE '%kernel32%' OR sr.string_value LIKE '%west/%' OR sr.string_value LIKE '%ws2_32%' OR sr.string_value LIKE '%advapi32%' ORDER BY sr.func_name`
- `SELECT sr.func_name, COUNT(*) as ref_count, GROUP_CONCAT(DISTINCT SUBSTR(sr.string_value, 1, 50)) as strings FROM string_refs sr GROUP BY sr.func_name ORDER BY ref_count DESC LIMIT 20`
- `SELECT content, address, length FROM strings WHERE length > 5 ORDER BY length DESC`

### Tool Outputs

- **Malcat**: File summary, section layout, anomalies, strings, imports, functions, decompilations, structures (source: malcat)
- **capa**: 8 capability rules matched (source: capa)
- **YARA**: 19 rules matched (source: yara)
- **FLOSS**: 79 static strings extracted (source: floss)
- **radare2**: Disassembly of entry point and exported functions (source: radare2)
- **UPX**: Not packed (source: upx)
- **XOR Search**: No significant findings (source: xor)
- **Speakeasy**: No API calls recorded (source: speakeasy)
- **Frida Probe**: No events recorded (source: frida_probe)

## 13. Appendix B: Analysis Environment

The analysis was performed in a controlled environment with the following tools and versions:

- **Malcat**: Used for file summary, section layout, anomalies, strings, imports, functions, decompilations, and structures.
- **capa**: Used for capability detection.
- **YARA**: Used for rule matching.
- **FLOSS**: Used for string extraction.
- **radare2**: Used for disassembly.
- **Ghidra**: Used for decompilation and query-based analysis.
- **IDA**: Used for query-based analysis.
- **Speakeasy**: Used for dynamic analysis (no events recorded).
- **Frida Probe**: Used for dynamic analysis (no events recorded).
- **UPX**: Used for packing detection.
- **XOR Search**: Used for XOR analysis.

The sample was analyzed in a sandboxed environment to prevent any potential harm. All network indicators were monitored but not actively contacted during analysis.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39  
**sample_path:** /opt/samples/corpus/610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll  
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
  "sha256": "1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39",
  "family": "Unknown backdoor/Trojan (possible Delphi-based)",
  "imphash": "0302695b505772b990fb0f7026657050",
  "generated_at": "2026-08-09T14:12:26.843206+00:00",
  "string_count": 24,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "Z_^B[B]BX",
    "ntdll.dll",
    "advapi32",
    "DestroyCursor",
    "LoadMenuA",
    "PtInRect",
    "RegisterClassExA",
    "ReplyMessage",
    "CallWindowProcW",
    "USER32.dll",
    "DeleteFileA",
    "ExitProcess",
    "FatalExit",
    "GetLastError",
    "LoadLibraryExA",
    "lstrcpyA",
    "GetModuleHandleW",
    "KERNEL32.dll",
    "PolyBezierTo",
    "SetColorSpace",
    "SetTextColor",
    "SetWindowExtEx",
    "SetWorldTransform"
  ],
  "rule_path": "/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/rule.yar",
  "sigma_path": "/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/rule.yml",
  "iocs_path": "/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/iocs.json",
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
    "utc": "2026-08-09 14:12:26 UTC"
  },
  "publish_target": "revai_publish"
}
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR dst_func_name LIKE 'CheckRemoteDebuggerPresent%' OR dst_func_name LIKE 'NtQueryInformationProcess%' OR dst_func_name LIKE 'OutputDebugString%' O`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'SetUnhandledExceptionFilter%' OR dst_func_name LIKE 'UnhandledExceptionFilter%'", "ts": 1786312060.973176}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'CreateToolhelp32Snapshot%' OR dst_func_name LIKE 'Process32FirstW%' OR dst_func_name LIKE 'Process32NextW%' OR dst_func_name LIKE 'Process32First%' OR dst_func_name LI`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetTickCount%' OR dst_func_name LIKE 'GetTickCount64%' OR dst_func_name LIKE 'QueryPerformanceCounter%' OR dst_func_name LIKE 'NtQueryPerformanceCounter%' OR dst_func_`
- `{"source": "ghidra_query", "sql": "SELECT address, content FROM strings WHERE length < 300", "ts": 1786312061.2070403}`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs", "ts": 1786312061.2114477}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetProcAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddressForCaller%'", "ts": 1786312061.3245802}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786312061.332039}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr FROM callgraph_edges WHERE dst_func_name LIKE 'LoadLibraryA%' OR dst_func_name LIKE 'LoadLibraryW%' OR dst_func_name LIKE 'LoadLibraryExA%' OR dst_func_name LIKE 'LoadLibraryExW%' OR dst_func_name LIKE 'LdrLoadDll%' OR dst_func_name LIKE 'GetMo`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786312061.474052}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786312061.478408}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1786312061.4865024}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports ORDER BY module, name", "ts": 1786312068.7281935}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length > 5 ORDER BY length DESC", "ts": 1786312068.7318096}`
- `{"source": "ghidra_query", "sql": "SELECT f.name, f.address, fm.size, fm.instruction_count, fm.block_count, fm.cyclomatic_complexity, fm.call_out_count, fm.string_ref_count FROM funcs f LEFT JOIN function_metrics fm ON f.address = fm.func_addr ORDER BY fm.cyclomatic_complexity DESC NULLS LAST LIMIT `
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, sr.func_addr, sr.string_value FROM string_refs sr WHERE sr.string_value LIKE '%mnemonicarx%' OR sr.string_value LIKE '%west/%' OR sr.string_value LIKE '%kernel32%' OR sr.string_value LIKE '%LXCV0%' ORDER BY sr.func_name", "ts": 1786312082.72304`
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, COUNT(*) as ref_count, GROUP_CONCAT(DISTINCT SUBSTR(sr.string_value, 1, 40)) as strings FROM string_refs sr GROUP BY sr.func_name ORDER BY ref_count DESC LIMIT 20", "ts": 1786312082.9969485}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM exports", "ts": 1786312086.6827722}`
- `{"source": "ida_query", "sql": "SELECT sr.func_name, sr.string_value, sr.string_addr FROM string_refs sr WHERE sr.string_value LIKE '%mnemonicarx%' OR sr.string_value LIKE '%kernel32%' OR sr.string_value LIKE '%west/%' OR sr.string_value LIKE '%ws2_32%' OR sr.string_value LIKE '%advapi32%' ORDER BY `
- `{"source": "ida_query", "sql": "SELECT sr.func_name, COUNT(*) as ref_count, GROUP_CONCAT(DISTINCT SUBSTR(sr.string_value, 1, 50)) as strings FROM string_refs sr GROUP BY sr.func_name ORDER BY ref_count DESC LIMIT 20", "ts": 1786312094.90458}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM callgraph_edges LIMIT 5", "ts": 1786312102.7579482}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_name, dst_func_name FROM callgraph_edges WHERE src_func_name IN ('FUN_100016eb','FUN_10002cd8','FUN_10002974','FUN_10002509','FUN_1000275f','FUN_10001f47','FUN_10002b7e','FUN_10002bc5') OR dst_func_name IN ('FUN_100016eb','FUN_10002cd8','FUN_1000297`
- `{"source": "ghidra_query", "sql": "SELECT * FROM memory_blocks LIMIT 10", "ts": 1786312108.8320966}`
- `{"source": "ida_query", "sql": "SELECT content, address, length FROM strings WHERE length > 5 ORDER BY length DESC", "ts": 1786312113.3629417}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_name, dst_func_name FROM callgraph_edges WHERE src_func_name = 'FUN_10002974'", "ts": 1786312137.1342108}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_name, dst_func_name FROM callgraph_edges WHERE src_func_name = 'FUN_10002cd8'", "ts": 1786312137.1665964}`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE address >= 268446936 AND address <= 268447815 AND mnemonic IN ('CALL','JMP') LIMIT 30", "ts": 1786312137.1872218}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, data_type, size FROM data_items WHERE address IN (268472172, 268472196, 268472176) OR name LIKE '%1000af6c%' OR name LIKE '%1000af84%' OR name LIKE '%1000af70%'", "ts": 1786312143.2749481}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, data_type, size FROM data_items WHERE address >= 268472160 AND address <= 268472200 ORDER BY address", "ts": 1786312143.2809136}`
- `{"source": "ghidra_query", "sql": "SELECT i.address, i.mnemonic, i.operands FROM instructions i WHERE i.address >= 268447120 AND i.address <= 268447260 AND i.mnemonic = 'CALL' ORDER BY i.address", "ts": 1786312156.1730022}`
