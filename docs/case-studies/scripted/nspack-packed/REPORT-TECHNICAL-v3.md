> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 15:05:58 UTC

# Technical Malware Analysis Report v3

## 1. Executive Summary

This report details the analysis of a PE executable (SHA256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5) identified as packed with nSpack v2.x. The sample masquerades as Windows Calculator (calc.exe) through forged Microsoft Corporation version information. Multiple analysis engines consistently identify nSpack packing through YARA signatures, string artifacts, and structural anomalies. The binary imports APIs for dynamic loading (LoadLibraryA), memory manipulation (VirtualAlloc, VirtualProtect), and registry access (RegOpenKeyExA), which are typical for packed executables but not inherently malicious. No overt malicious behavior such as command-and-control communication, data exfiltration, or destructive actions was observed during static analysis. The sample is classified as suspicious due to its packing and obfuscation, but without clear evidence of hostile intent. Dynamic analysis tools (Speakeasy, Frida) recorded no API calls or events, indicating the sample may require specific conditions to execute its payload or may be a benign packed application.

## 2. Sample Metadata

| Attribute | Value |
|---|---|
| SHA256 | 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5 |
| File Path | /opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe |
| Project Name | Hexorcist 1 - Weeks 1-8 |
| File Type | PE (Portable Executable) |
| Architecture | X86 |
| File Size | 55021 bytes |
| Entry Point EA | 27 |
| Overall Entropy | 52 |
| Verdict | Suspicious (score: 50) |
| Family Guess | nSpack |
| Source | llm_judge (model: mimo-v2.5-pro) |

## 3. File Layout & Structural Analysis

The PE file exhibits significant structural anomalies consistent with packing. The file contains two primary sections named `nsp0` and `nsp1`, which are non-standard section names typically associated with nSpack. Both sections have Read-Write-Execute (RWX) permissions, a classic indicator of self-modifying code used during unpacking. The virtual sizes of the sections are substantially larger than their physical sizes, indicating compressed or encrypted content that will be expanded at runtime.

**Section Layout (source: malcat)**
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| nsp0 | 0 | 512 | 122880 | 52 | RWX |
| nsp1 | 122880 | 54509 | 65536 | 0 | RWX |

The `nsp0` section has high entropy (52), suggesting compressed or encrypted data, while `nsp1` shows zero entropy, which may indicate uninitialized or zero-filled space that will be populated during unpacking. The RWX permissions on both sections allow the packer stub to write decompressed code into these sections and then execute it.

**Structural Anomalies (source: malcat)**
The analysis identified 16 anomalies, with several high-signal indicators:
- **CrossSectionJump** (Level 4): Control flow jumps across sections, typical for packed files where the stub transfers execution to the unpacked payload.
- **SectionWX** (Level 3): Both `nsp0` and `nsp1` are executable and writable, enabling self-modifying code.
- **Packed** (Level 2): Multiple packing anomalies detected.
- **GuiSubsystemNoWindowApi** (Level 2): A GUI application that does not import any user32 window-related functions, which is unusual for a legitimate calculator application.
- **UnreferencedImports** (Level 3): More than half of the imports are not referenced, suggesting decoy imports or APIs used only during runtime unpacking.

These anomalies collectively indicate a packed executable with obfuscated control flow and self-modifying capabilities.

## 4. Static Code Analysis

### Entry Point and Packer Stub
The entry point at EA 27 immediately jumps to the main packer stub function at `0x01025a56` (source: radare2). This function is complex with cyclomatic complexity of 18 and 27 basic blocks (source: deep_dive_agentic), indicating obfuscated control flow typical of packers.

**Entry Point Disassembly (source: radare2)**
```asm
0x0100101b      e9364a0200     jmp fcn.01025a56
```
This jump transfers control to the packer initialization routine.

**Packer Stub Initialization (source: radare2)**
The function at `0x01025a56` begins by saving all registers and flags, then performs position-independent code (PIC) techniques to determine its own address:
```asm
0x01025a56      9c             pushfd
0x01025a57      60             pushal
0x01025a58      e800000000     call 0x1025a5d
0x01025a5d      5d             pop ebp
0x01025a5e      b807000000     mov eax, 7
0x01025a63      2be8           sub ebp, eax
```
The `call/pop` sequence is a classic PIC technique to obtain the current instruction pointer (EIP), which is essential for position-independent unpacking code. This matches the YARA rule `maldoc_getEIP_method_1` (source: yara).

### API Resolution and Memory Manipulation
The packer stub dynamically resolves APIs using `LoadLibraryA` and `GetProcAddress` (source: malcat imports). It then uses `VirtualAlloc` to allocate memory for the unpacked payload and `VirtualProtect` to change memory permissions as needed during unpacking.

**Key API Imports (source: malcat)**
| EA | Name | Type | Refs |
|---|---|---|---|
| 149636 | kernel32.LoadLibraryA | IMPORT | 1 |
| 149640 | kernel32.GetProcAddress | IMPORT | 0 |
| 149644 | kernel32.VirtualProtect | IMPORT | 0 |
| 149648 | kernel32.VirtualAlloc | IMPORT | 0 |
| 149652 | kernel32.VirtualFree | IMPORT | 0 |
| 149680 | advapi32.RegOpenKeyExA | IMPORT | 1 |

The presence of `RegOpenKeyExA` suggests potential registry access, though no specific registry keys were identified in static analysis. The `GetProcAddress` import has zero references, indicating it may be resolved dynamically or used only during runtime.

### Decompression Routine
The packer uses aPLib decompression to extract the hidden payload (source: capa). The decompiled function `sub_1025d7f` (source: malcat) shows complex bit manipulation and loop structures characteristic of aPLib decompression algorithms. This function processes compressed data byte-by-byte, using carry flags and conditional jumps to reconstruct the original payload.

**Decompilation of Decompression Function (source: malcat)**
The function `sub_1025d7f` implements aPLib decompression with parameters for source and destination buffers. It uses bit-level operations to decode literal bytes and copy sequences from previously decompressed data, which is the hallmark of aPLib compression.

### Version Information Masquerade
The binary contains forged version information claiming to be "Microsoft Windows Calculator" (CALC.EXE) version 5.1.2600.0 by Microsoft Corporation (source: malcat strings). This is a social engineering technique to appear legitimate.

**Version Strings (source: malcat)**
- EA 124732: `Windows Calculat..application file`
- EA 125116: `CALC.EXE`
- EA 124836: `5.1.2600.0 (xpcl..ent.010817-1148)`
- EA 124648: `Microsoft Corporation`

## 5. Behavioral & Dynamic Analysis

### Speakeasy Emulation
Speakeasy emulation recorded zero API calls and zero key events (source: speakeasy). This indicates the sample did not execute any observable behavior during emulation, which could mean:
1. The sample requires specific environmental conditions not present in the emulator.
2. The sample is a benign packed application that performs no malicious actions.
3. The emulation environment detected and avoided execution.

### Frida Probe
Frida was available (version 17.16.4) and identified 10 hook candidates (source: frida_probe), including the key APIs imported by the sample. However, no runtime behavior was observed, consistent with the Speakeasy results.

**Hook Candidates (source: frida_probe)**
- `KERNEL32.DLL!LoadLibraryA`
- `KERNEL32.DLL!GetProcAddress`
- `KERNEL32.DLL!VirtualProtect`
- `KERNEL32.DLL!VirtualAlloc`
- `KERNEL32.DLL!VirtualFree`
- `SHELL32.DLL!ShellAboutW`
- `MSVCRT.DLL!__CxxFrameHandler`
- `ADVAPI32.DLL!RegOpenKeyExA`
- `GDI32.DLL!SetBkColor`
- `USER32.DLL!GetMenu`

The lack of observed behavior suggests the sample may be inert in the analysis environment or requires user interaction to trigger.

## 6. Network Indicators & C2

No network indicators or command-and-control (C2) infrastructure were identified during static analysis. YARA rules detected potential IP addresses and domains, but these appear to be embedded in the packed data rather than active C2 endpoints.

**YARA Network Indicators (source: yara)**
- `IP` rule matched at offset 3242 (length 7) and offset 6033 (length 2).
- `domain` rule matched at offset 0 (length 2).

These matches are likely false positives or artifacts within the compressed payload. Without runtime unpacking, their actual purpose cannot be determined. No network-related API calls (e.g., `WinHTTP`, `WinInet`, `WS2_32`) were imported, further suggesting no active network communication capabilities in the packer stub.

## 7. Capabilities Assessment

Based on static analysis, the sample possesses the following capabilities:

1. **Packing and Obfuscation**: Uses nSpack v2.x with aPLib compression to hide the original payload (source: yara, capa, floss).
2. **Self-Modifying Code**: RWX sections allow runtime code modification (source: malcat sections).
3. **Dynamic API Resolution**: Uses `LoadLibraryA` and `GetProcAddress` to resolve APIs at runtime, hindering static analysis (source: malcat imports).
4. **Memory Manipulation**: `VirtualAlloc`, `VirtualFree`, and `VirtualProtect` enable dynamic memory management for unpacking (source: malcat imports).
5. **Registry Access**: `RegOpenKeyExA` import suggests potential registry interaction, though no specific keys were identified (source: malcat imports).
6. **Social Engineering**: Masquerades as Windows Calculator with forged version information (source: malcat strings).

No capabilities for data exfiltration, persistence, credential access, or defense evasion beyond packing were observed. The actual payload capabilities are unknown without runtime unpacking.

## 8. Indicators of Compromise

### File-Based IOCs
| Type | Value | Source |
|---|---|---|
| SHA256 | 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5 | malcat |
| File Name | nspack.exe | malcat |
| Packer | nSpack v2.x | yara, floss, packer_intake |
| Section Names | nsp0, nsp1 | malcat |
| Version Info | Microsoft Windows Calculator (CALC.EXE) v5.1.2600.0 | malcat strings |

### String-Based IOCs
| String | EA | Source |
|---|---|---|
| `!packed by nspack$@` | N/A | floss |
| `KERNEL32.DLL` | 149844 | malcat |
| `LoadLibraryA` | 149916 | malcat |
| `GetProcAddress` | 149931 | malcat |
| `VirtualProtect` | 149948 | malcat |
| `VirtualAlloc` | 149965 | malcat |
| `VirtualFree` | 149980 | malcat |
| `RegOpenKeyExA` | N/A | malcat imports |

### YARA Rule Matches
| Rule | Namespace | Match Strings |
|---|---|---|
| nSpackV2xLiuXingPing | - | $a0@27734 len=17 |
| NsPackV2XLiuXingPing | - | $a0@53 len=8 |
| NsPackv23NorthStar | - | $a0@27734 len=85; $a1@27734 len=141 |
| maldoc_getEIP_method_1 | - | $a@27736 len=6 |
| win_registry | - | $f1@27512 len=12; $c2@27674 len=13 |
| IP | - | $ipv4@3242 len=7; $ipv6@6033 len=2 |
| contains_base64 | - | $a@3112 len=16 |

## 9. Detection Engineering

### YARA Rules
The following YARA rules are effective for detecting this sample:
1. **nSpackV2xLiuXingPing**: Detects nSpack packer signature at offset 27734.
2. **NsPackv23NorthStar**: Detects nSpack v2.3 NorthStar variant with multiple string matches.
3. **maldoc_getEIP_method_1**: Detects position-independent code technique for obtaining EIP.
4. **win_registry**: Detects registry-related strings that may indicate persistence or configuration.

### Behavioral Indicators
- **RWX Sections**: Sections with Read-Write-Execute permissions are suspicious and should be monitored.
- **Dynamic API Resolution**: Calls to `LoadLibraryA` and `GetProcAddress` in sequence may indicate runtime API resolution.
- **Packer Section Names**: Non-standard section names like `nsp0` and `nsp1` are indicators of nSpack.
- **Forged Version Information**: Applications claiming to be Microsoft utilities but lacking valid digital signatures.

### Detection Gaps
- The actual payload is encrypted/compressed and not accessible statically.
- No network indicators were confirmed as active C2.
- Dynamic analysis did not reveal runtime behavior, limiting behavioral detection rules.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Defense Evasion | Obfuscated Files or Information | T1027 | nSpack packing with aPLib compression (source: yara, capa) |
| Defense Evasion | Process Injection | T1055 | VirtualProtect import for memory permission changes (source: pe_imports) |
| Execution | Shared Modules | T1129 | LoadLibraryA and GetProcAddress for dynamic API resolution (source: pe_imports) |
| Discovery | System Information Discovery | T1082 | Potential registry access via RegOpenKeyExA (source: malcat imports) |
| Persistence | Boot or Logon Autostart Execution | T1547 | Registry access may indicate persistence mechanisms (source: yara win_registry) |

Note: The mapping is based on imported APIs and structural characteristics. Actual technique execution was not observed during dynamic analysis.

## 11. What We Don't Know

1. **Actual Payload Purpose**: The compressed/encrypted payload within the nsp1 section cannot be analyzed statically. Its capabilities, intent, and maliciousness are unknown.
2. **Runtime Behavior**: Dynamic analysis tools recorded no API calls or events. We do not know if the sample requires specific triggers (e.g., user interaction, environmental conditions) to execute.
3. **Network Communication**: While YARA detected potential IP addresses and domains, their actual use for C2 or data exfiltration is unconfirmed.
4. **Persistence Mechanisms**: Registry access APIs are imported, but no specific registry keys or persistence techniques were identified.
5. **Credential Access**: No APIs for credential harvesting (e.g., `CryptUnprotectData`, token manipulation) were observed, but the payload may contain such capabilities.
6. **Defense Evasion Beyond Packing**: The sample uses packing and dynamic API resolution, but other evasion techniques (e.g., anti-debugging, anti-VM) were not identified.
7. **Lateral Movement or Propagation**: No evidence of network propagation or lateral movement techniques was found.
8. **Data Collection or Exfiltration**: No data staging or exfiltration APIs were imported, but the payload may implement these.

## 12. Appendix A: Tool Evidence Trail

### Analysis Tools Used
- **Malcat**: File structure, sections, imports, strings, anomalies, decompilation.
- **YARA**: Rule matching for packer detection and IOC identification.
- **FLOSS**: String extraction, including decoded and static strings.
- **capa**: Capability detection (aPLib decompression).
- **radare2**: Disassembly and control flow analysis.
- **Speakeasy**: Dynamic emulation (no behavior observed).
- **Frida**: Runtime hooking candidates identified (no behavior observed).
- **UPX**: Attempted unpacking (failed, as sample uses nSpack, not UPX).
- **XOR Search**: Basic XOR analysis (no significant findings).

### Key Evidence Citations
1. **Packer Identification**: YARA rules `nSpackV2xLiuXingPing` and `NsPackv23NorthStar` matched (source: yara).
2. **String Artifact**: FLOSS extracted `!packed by nspack$@` (source: floss).
3. **Structural Anomalies**: Malcat identified 16 anomalies including `Packed`, `SectionWX`, and `CrossSectionJump` (source: malcat).
4. **API Imports**: Malcat listed 11 imports including `LoadLibraryA`, `VirtualProtect`, and `RegOpenKeyExA` (source: malcat).
5. **Decompression Capability**: capa detected `decompress data using aPLib` (source: capa).
6. **Version Masquerade**: Malcat strings show forged Windows Calculator version information (source: malcat).
7. **Dynamic Analysis Null Results**: Speakeasy and Frida recorded no runtime behavior (source: speakeasy, frida_probe).

## 13. Appendix B: Analysis Environment

- **Sample Path**: /opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe
- **Project Name**: Hexorcist 1 - Weeks 1-8
- **Analysis Tools**: Malcat, YARA, FLOSS, capa, radare2, Speakeasy, Frida, UPX, XOR Search.
- **Dynamic Analysis**: Speakeasy emulation and Frida probing were performed but yielded no observable behavior.
- **Static Analysis**: Comprehensive static analysis was conducted using multiple tools to identify packing, imports, strings, and structural anomalies.
- **Limitations**: The sample's packing prevented full static analysis of the payload. Dynamic analysis did not trigger execution, possibly due to environmental requirements or sample inertness.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5  
**sample_path:** /opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe  
**project_name:** Hexorcist 1 - Weeks 1-8

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 50
- **family_guess**: nSpack
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Multiple tools (packer_intake, yara, floss, malcat) consistently identify nSpack packing. Ghidra reports fewer functions and strings (4 vs 7 in IDA) due to packing obfuscation, while IDA and MalCat agree on imports including memory manipulation APIs. No clear behavioral-intent evidence (e.g., C2, data destruction) is found across engines.
- **summary**: The sample is packed with nSpack, evidenced by YARA signatures, floss strings, and packer analysis, with high entropy and section anomalies. It imports APIs for dynamic loading and memory protection (e.g., LoadLibraryA, VirtualProtect), but no overt malicious behavior like C2 communication or data destruction is detected. Thus, it is classified as suspicious, likely a packed executable without clear hostile intent.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| packer_intake | label | `packed` | Deterministic analysis flags the sample as packed with high entropy exec sections (e.g., nsp1 entropy 6.961), section mi |
| yara | - | `nSpackV2xLiuXingPing rule match` | YARA rule specifically detects nSpack packer signature, confirming the packer identification. |
| floss | - | `!packed by nspack$@` | String explicitly states 'packed by nspack', providing direct evidence of nSpack packing. |
| pe_imports | - | `load_library (LoadLibraryA) with attack T1129` | Import of LoadLibraryA enables dynamic library loading, a common technique in packed and potentially malicious code for  |
| malcat | - | `Packed×2` | MalCat detects multiple packing anomalies, reinforcing the obfuscation indication from other tools. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE executable packed with nSpack v2.x that masquerades as Windows Calculator (calc.exe). The binary uses forged Microsoft Corporation version info to disguise itself. It contains aPLib decompression routines, VirtualAlloc/VirtualProtect for memory manipulation, dynamic API resolution via LoadLibraryA/GetProcAddress, and registry access (RegOpenKeyExA). Both code sections (nsp0/nsp1) have RWX permissions indicating self-modifying unpacking code. YARA rules detect embedded IP addresses, registry keys, base64-encoded data, and position-independent code techniques. The actual malicious payload is compressed/encrypted and only revealed at runtime after unpacking. Persistence mechanisms were not observed {analysis tools, behavior monitoring, no persistence indicators, lacking registry key modifications for auto-start}. Exfiltration techniques were not identified {analysis tools, network traffic analysis, no exfiltration patterns, missing data transfer calls}. Defense impairment is suggested by RWX code sections {disassembly analysis, section attributes, nsp0/nsp1 with RWX, enables self-modifying code to evade detection} and dynamic API resolution {API hooking analysis, LoadLibraryA/GetProcAddress calls, hinders static analysis and signature-based detection}. Credential access methods were not observed {analysis tools, API call tracing, no credential access APIs, lacking functions like CryptUnprotectData or token manipulation}.

### deep key_evidence
- `"YARA rules nSpackV2xLiuXingPing and NsPackv23NorthStar matched; string '!packed by nspack$@' at file offset confirms nSpack v2.x packer"`
- `"Version info masquerades as 'Microsoft Windows Calculator' (CALC.EXE) v5.1.2600.0 by Microsoft Corporation \u2014 forged metadata on a packed binary"`
- `"Imports include VirtualAlloc, VirtualFree, VirtualProtect, LoadLibraryA, GetProcAddress, RegOpenKeyExA \u2014 APIs associated with unpacking, dynamic resolution, and registry access"`
- `"capa detected 'decompress data using aPLib' (C0025.003) \u2014 the packer uses aPLib to decompress the hidden payload at runtime"`
- `"Sections nsp0 (122880 bytes) and nsp1 (61520 bytes) both have RWX permissions (is_read=1, is_write=1, is_exec=1) \u2014 classic self-modifying code indicator"`
- `"YARA win_registry rule hit at offsets 27512 and 27674; IP rule hit at offset 3242; contains_base64 hit at offset 3112; maldoc_getEIP_method_1 hit at offset 27736"`
- `"Main function FUN_01025d7f has cyclomatic complexity 18 with 27 basic blocks indicating obfuscated control flow in the packer stub"`
- `"Only 4 functions identified statically \u2014 the real payload is hidden inside the compressed nsp1 section and not accessible without runtime unpacking"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5
size: 55021
type: PE
architecture: X86
entrypoint_ea: 27
entropy: 52
file_name: nspack.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| nsp0 | 0 | 512 | 122880 | 52 | RWX |
| nsp1 | 122880 | 54509 | 65536 | 0 | RWX |

### Malcat YARA / Signatures (3)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2002_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| nspack_23_02 | packer | INFO | 50 |  |
| nspack_23_03 | packer | INFO | 50 |  |

### Anomalies (16)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 2 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| PointerToRawDataNotAligned | 4 | sections | 1 | PointerToRawData is not aligned to FileAlignment |
| SizeOfRawDataNotAligned | 4 | sections | 2 | SizeOfRawData is not aligned to FileAlignment |
| UnsignedMicrosoft | 4 | integrity | 3 | Version information tells us it is a microsoft file but no certificate has been found |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 11 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| InvalidSizeOfUninitializedData | 2 | sections | 1 | SizeOfUninitializedData is not the sum of all uninitalized data sections (raw or virtual) |
| Packed | 2 | packers | 2 | File is packed using a legit or less-legit obfuscator |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `156`: 

### High-Signal Strings (4 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 149844 | `KERNEL32.DLL` |
| 149931 | `GetProcAddress` |
| 149916 | `LoadLibraryA` |
| 149948 | `VirtualProtect` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 125372 | `<?xml version="1..>
</assembly>
` |
| 149880 | `ADVAPI32.DLL` |
| 149857 | `SHELL32.DLL` |
| 149844 | `KERNEL32.DLL` |
| 149893 | `GDI32.DLL` |
| 149903 | `USER32.DLL` |
| 149869 | `MSVCRT.DLL` |
| 124986 | ` Microsoft Corpo..rights reserved.` |
| 124732 | `Windows Calculat..application file` |
| 125116 | `CALC.EXE` |
| 124836 | `5.1.2600.0 (xpcl..ent.010817-1148)` |
| 124648 | `Microsoft Corporation` |
| 124470 | `VS_VERSION_INFO` |
| 124598 | `040904B0` |
| 125082 | `OriginalFilename` |
| 125280 | `5.1.2600.0` |
| 126338 | ```````` |
| 126402 | ```````` |
| 126912 | `fDDDDDD@offffff@n`` |
| 126274 | ``````` |
| 126951 | `@offffff@n` |
| 129984 | `xrssssvvvv` |
| 126290 | `opopopopowwpf@` |
| 130032 | `^zwurqqqqqsssssvvvv;` |
| 124910 | `InternalName` |
| 130367 | `YYYYXXV` |
| 124698 | `FileDescription` |
| 126934 | `p@offffff@n`` |
| 126522 | `fffff@` |
| 126498 | ``wwwwwwwfffff@` |
| 126490 | `fffff@` |
| 126466 | ``wwwwwwwfffff@` |
| 126354 | `opopopopopopf@` |
| 126418 | `opopopopopopf@` |
| 125250 | `ProductVersion` |
| 124562 | `StringFileInfo` |
| 124810 | `FileVersion` |
| 126993 | `ffffffa` |
| 124622 | `CompanyName` |
| 130429 | `XXXXXVX` |
| 126241 | `dDDDDDDDDDDDDD@` |
| 125342 | `Translation` |
| 124936 | `CALC` |
| 125206 | ` Operating System` |
| 126962 | `wwwff@o` |
| 124954 | `LegalCopyright` |
| 126545 | `ffffffffffffffa` |
| 126450 | `fffffffffffff@` |
| 126386 | `fffffffffffff@` |
| 126322 | `fffffffffffff@` |
| 126258 | `fffffffffffff@` |
| 125168 | `Microsoft` |
| 150022 | `__CxxFrameHandler` |
| 130083 | `^;LLZZzxxwtrqqrZ` |
| 132740 | `edddc` |
| 129755 | `hbbbe` |
| 149931 | `GetProcAddress` |
| 128154 | `B--B5J` |
| 125142 | `ProductName` |
| 128560 | `6=cc=4` |
| 130140 | `f^NLLL` |
| 125310 | `VarFileInfo` |
| 149916 | `LoadLibraryA` |
| 149948 | `VirtualProtect` |
| 143587 | `988` |
| 129265 | `MM8L` |
| 173184 | `RGGI` |
| 128935 | `>887` |
| 128784 | `]::9` |
| 171181 | `MQ5Q` |
| 172848 | `BtqB` |
| 126981 | `ff@o` |
| 176988 | `X^h^` |
| 126973 | `ff@n` |
| 156950 | `A<<` |
| 152223 | `@9A@` |
| 163075 | `Gt`t` |
| 163322 | `FX-F` |
| 149965 | `VirtualAlloc` |
| 149980 | `VirtualFree` |

### Imports (11)
| EA | Name | Type | Refs |
|---|---|---|---|
| 149636 | kernel32.LoadLibraryA | IMPORT | 1 |
| 149640 | kernel32.GetProcAddress | IMPORT | 0 |
| 149644 | kernel32.VirtualProtect | IMPORT | 0 |
| 149648 | kernel32.VirtualAlloc | IMPORT | 0 |
| 149652 | kernel32.VirtualFree | IMPORT | 0 |
| 149656 | kernel32.ExitProcess | IMPORT | 0 |
| 149664 | shell32.ShellAboutW | IMPORT | 1 |
| 149672 | msvcrt.__CxxFrameHandler | IMPORT | 1 |
| 149680 | advapi32.RegOpenKeyExA | IMPORT | 1 |
| 149688 | gdi32.SetBkColor | IMPORT | 1 |
| 149696 | user32.GetMenu | IMPORT | 1 |

### Functions (7)
| EA | Name |
|---|---|
| 27 | EntryPoint |
| 150102 | sub_1025a56 |
| 150911 | sub_1025d7f |
| 151070 | sub_1025e1e |
| 151038 | sub_1025dfe |
| 151048 | sub_1025e08 |
| 151066 | sub_1025e1a |

### Decompilations (top 6)
#### 27 — EntryPoint
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}

```
#### 150102 — sub_1025a56
```c
sub_1025a56 {
    // Error while decompiling : not a valid ea
}

```
#### 150911 — sub_1025d7f
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_1025d7f(uint8_t *param_1,uint8_t *param_2)

{
    char cVar1;
    undefined4 uVar3;
    uint8_t *puVar4;
    int32_t extraout_ECX;
    int32_t extraout_ECX_00;
    int32_t extraout_ECX_01;
    int32_t extraout_ECX_02;
    int32_t extraout_ECX_03;
    int32_t iVar5;
    uint8_t *puVar6;
    undefined in_CF;
    bool bVar7;
    uint8_t uVar8;
    uint8_t uVar2;
    
    do {
        puVar6 = param_1 + 1;
        *param_2 = *param_1;
        param_2 = param_2 + 1;
        while (sub_1025dfe(), param_1 = puVar6, in_CF) {
            bVar7 = false;
            sub_1025dfe();
            if (bVar7) {
                uVar8 = false;
                uVar3 = sub_1025dfe();
                if (!uVar8) {
                    puVar4 = CONCAT31(uVar3 >> 8, *puVar6) >> 1;
                    if (puVar4 == 0x0) {
                        return;
                    }
                    iVar5 = extraout_ECX + 2 + ((*puVar6 & 1) != 0);
                    puVar6 = puVar6 + 1;
                    goto code_r0x01025df4;
                }
                do {
                    uVar3 = sub_1025dfe();
                    uVar2 = uVar3;
                    bVar7 = CARRY1(uVar2 * '\x02', uVar8);
                    in_CF = CARRY1(uVar2, uVar2) || bVar7;
                    cVar1 = uVar2 * '\x02' + uVar8;
                    puVar4 = CONCAT31(uVar3 >> 8, cVar1);
                    uVar8 = in_CF;
                } while (!CARRY1(uVar2, uVar2) && !bVar7);
                iVar5 = extraout_ECX_00;
                if (cVar1 != '\0') goto code_r0x01025df3;
                *param_2 = 0;
                param_2 = param_2 + 1;
            }
            else {
                func_0x01025e0a();
                if (extraout_ECX_01 == 2) {
                    puVar4 = sub_1025e08();
                    iVar5 = extraout_ECX_02;
                }
                else {
                    puVar6 = puVar6 + 1;
                    puVar4 = sub_1025e08();
                    if (puVar4 < 0x7d00) {
                        iVar5 = extraout_ECX_03;
                        if (0x4ff < puVar4) goto code_r0x01025df3;
                        if (0x7f < puVar4) goto code_r0x01025df4;
                    }
                    iVar5 = extraout_ECX_03 + 1;
code_r0x01025df3:
                    iVar5 = iVar5 + 1;
                }
code_r0x01025df4:
                in_CF = param_2 < puVar4;
                puVar4 = param_2 + -puVar4;
                for (; iVar5 != 0; iVar5 = iVar5 + -1) {
                    *param_2 = *puVar4;
                    puVar4 = puVar4 + 1;
                    param_2 = param_2 + 1;
                }
            }
        }
    } while( true );
}

```

### Carved Files (8)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 3752 |
| ? | DIB | 2216 |
| ? | DIB | 1384 |
| ? | DIB | 9640 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |

### Virtual Files (11)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/en-us | 744 | - |
| ICO/2/en-us | 296 | - |
| ICO/3/en-us | 3752 | - |
| ICO/4/en-us | 2216 | - |
| ICO/5/en-us | 1384 | - |
| ICO/6/en-us | 9640 | - |
| ICO/7/en-us | 4264 | - |
| ICO/8/en-us | 1128 | - |
| GRPICO/SC/en-us | 118 | - |
| VER/1/en-us | 908 | - |
| MANIF/1/en-us | 667 | - |

### Structures (85)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 64 |
| OptionalHeader | 88 |
| Sections | 312 |
| Resources | 122880 |
| Resources.ICO | 122960 |
| Resources.ICO.1 | 123040 |
| Resources.ICO.1.en-us | 123064 |
| Resources.ICO.2 | 123080 |
| Resources.ICO.2.en-us | 123104 |
| Resources.ICO.3 | 123120 |
| Resources.ICO.3.en-us | 123144 |
| Resources.ICO.4 | 123160 |
| Resources.ICO.4.en-us | 123184 |
| Resources.ICO.5 | 123200 |
| Resources.ICO.5.en-us | 123224 |
| Resources.ICO.6 | 123240 |
| Resources.ICO.6.en-us | 123264 |
| Resources.ICO.7 | 123280 |
| Resources.ICO.7.en-us | 123304 |
| Resources.ICO.8 | 123320 |
| Resources.ICO.8.en-us | 123344 |
| Resources.MENU | 123360 |
| Resources.MENU.106 | 123408 |
| Resources.MENU.106.en-us | 123432 |
| Resources.MENU.107 | 123448 |
| Resources.MENU.107.en-us | 123472 |
| Resources.MENU.108 | 123488 |
| Resources.MENU.108.en-us | 123512 |
| Resources.MENU.109 | 123528 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.82

| Rule | ATT&CK | MBC |
|---|---|---|
| decompress data using aPLib |  | C0025.003:Decompress Data |

## PE Imports / Signals
import_count: 11

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 12

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@3242 len=7; $ipv6@6033 len=2 |
| contains_base64 | - | $a@3112 len=16 |
| nSpackV2xLiuXingPing | - | $a0@27734 len=17 |
| NsPackV2XLiuXingPing | - | $a0@53 len=8 |
| NsPackv23NorthStar | - | $a0@27734 len=85; $a1@27734 len=141 |
| maldoc_getEIP_method_1 | - | $a@27736 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasModified_DOS_Message | - |  |
| suspicious_packer_section | - |  |
| win_registry | - | $f1@27512 len=12; $c2@27674 len=13 |

## Generated YARA Meta
```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
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
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3242,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 6033,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 3112,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "nSpackV2xLiuXingPing",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 27734,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "NsPackV2XLiuXingPing",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 53,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "NsPackv23NorthStar",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 27734,
          "length": 85,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 27734,
          "length": 141,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 27736,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "suspicious_packer_section",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": []
    },
    {
      "rule": "win_registry",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe",
      "strings": [
        {
          "id": "$f1",
          "offset": 27512,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 27674,
          "length": 13,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unkn
```

## FLOSS Strings
Total strings: 169 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 169}`

### High-signal FLOSS
- `KERNEL32.DLL`
- `LoadLibraryA`
- `GetProcAddress`
- `VirtualProtect`

### FLOSS sample
- `!packed by nspack$@`
- `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
- `<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">`
- `<assemblyIdentity`
- `name="Microsoft.Windows.Shell.calc"`
- `processorArchitecture="x86"`
- `version="5.1.0.0"`
- `type="win32"/>`
- `<description>Windows Shell</description>`
- `<dependency>`
- `<dependentAssembly>`
- `type="win32"`
- `name="Microsoft.Windows.Common-Controls"`
- `version="6.0.0.0"`
- `publicKeyToken="6595b64144ccf1df"`
- `language="*"`
- `</dependentAssembly>`
- `</dependency>`
- `</assembly>`
- `dDDDDDDDDDDDDD@`
- `fffffffffffff@`
- `opopopopowwpf@`
- `opopopopopopf@`
- ``wwwwwwwfffff@`
- `fffff@`
- `ffffffffffffffa`
- `fDDDDDD@offffff@n``
- `p@offffff@n``
- `@offffff@n`
- `wwwff@o`
- `ffffffa`
- `B--B5J`
- `|||ddcO87`
- `c||cO87`
- `=||ccOM7`
- `6=cc=4`
- ``NfOM79|?4`
- ``~bbbi`
- `xrssssvvvv`
- `^zwurqqqqqsssssvvvv;`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0100101b
```asm
┌ 5: entry0 ();
└       ┌─< 0x0100101b      e9364a0200     jmp fcn.01025a56
```
### 0x01025a56
```asm
╎   ; CODE XREF from entry0 @ 0x100101b(x)
├ 648: fcn.01025a56 ();
│       ╎   ; var int32_t var_1beh @ ebp-0x1be
│       ╎   ; var int32_t var_1c2h @ ebp-0x1c2
│       ╎   ; var int32_t var_1c6h @ ebp-0x1c6
│       ╎   ; var int32_t var_1cah @ ebp-0x1ca
│       ╎   ; var int32_t var_1fah @ ebp-0x1fa
│       ╎   ; var int32_t var_202h @ ebp-0x202
│       ╎   ; var int32_t var_212h @ ebp-0x212
│       ╎   ; var int32_t var_22ah @ ebp-0x22a
│       ╎   ; var int32_t var_23eh @ ebp-0x23e
│       ╎   ; var int32_t var_246h @ ebp-0x246
│       ╎   ; var int32_t var_26eh @ ebp-0x26e
│       ╎   ; var int32_t var_27eh @ ebp-0x27e
│       ╎   0x01025a56      9c             pushfd
│       ╎   0x01025a57      60             pushal
│       ╎   0x01025a58      e800000000     call 0x1025a5d
│       ╎   ; CALL XREF from fcn.01025a56 @ 0x1025a58(x)
│       ╎   0x01025a5d      5d             pop ebp
│       ╎   0x01025a5e      b807000000     mov eax, 7
│       ╎   0x01025a63      2be8           sub ebp, eax
│       ╎   0x01025a65      8db5d6fdffff   lea esi, [var_22ah]
│       ╎   0x01025a6b      8b06           mov eax, dword [esi]
│       ╎   0x01025a6d      83f800         cmp eax, 0
│      ┌──< 0x01025a70      7411           je 0x1025a83
│      │╎   0x01025a72  ~   8db5fefdffff   lea esi, [var_202h]
..
│      │╎   0x01025a78      8b06           mov eax, dword [esi]
│      │╎   0x01025a7a      83f801         cmp eax, 1                  ; 1
│     ┌───< 0x01025a7d      0f844b020000   je 0x1025cce
│     │└──> 0x01025a83  ~   c70601000000   mov dword [esi], 1
..
│     │ ╎   0x01025a89      8bd5           mov edx, ebp
│     │ ╎   0x01025a8b      8b8592fdffff   mov eax, dword [var_26eh]
│     │ ╎   0x01025a91      2bd0           sub edx, eax
│     │ ╎   0x01025a93      899592fdffff   mov dword [var_26eh], edx
│     │ ╎   0x01025a99      0195c2fdffff   add dword [var_23eh], edx
│     │ ╎   0x01025a9f      8db506feffff   lea esi, [var_1fah]
│     │ ╎   0x01025aa5      0116           add dword [esi], edx
│     │ ╎   0x01025aa7      8b36           mov esi, dword [esi]
│     │ ╎   0x01025aa9      8bfd           mov edi, ebp
│     │ ╎   0x01025aab      60             pushal
│     │ ╎   0x01025aac      6a40           push 0x40                   ; pe_nt_image_headers32
│     │ ╎   0x01025aae      6800100000     push 0x1000
│     │ ╎   0x01025ab3      6800100000     push 0x1000
│     │ ╎   0x01025ab8      6a00           push 0
│     │ ╎   0x01025aba      ff953afeffff   call dword [var_1c6h]
│     │ ╎   0x01025ac0      85c0           test eax, eax
│     │┌──< 0x01025ac2      0f8456030000   je 0x1025e1e
│     ││╎   0x01025ac8      8985bafdffff   mov dword [var_246h], eax
│     ││╎   0x01025ace      e800000000     call 0x1025ad3
│     ││╎   ; CALL XREF from fcn.01025a56 @ 0x1025ace(x)
│     ││╎   0x01025ad3      5b             pop ebx
│     ││╎   0x01025ad4      b954030000     mov ecx, 0x354              ; 852
│     ││╎   0x01025ad9      03d9           add ebx, ecx
│     ││╎   0
```
### 0x01025884
```asm
│           ;-- (0x01025888) GetProcAddress:
┌ 532: sym.imp.KERNEL32.DLL_LoadLibraryA (int32_t arg_53h, int32_t arg_59h, int32_t arg_78h);
│           ; arg int32_t arg_53h @ ebp+0x53
│           ; arg int32_t arg_59h @ ebp+0x59
│           ; arg int32_t arg_78h @ ebp+0x78
│           ; var int32_t var_48h @ ebp-0x48
│           ; var int32_t var_1beh @ ebp-0x1be
│           ; var int32_t var_1c2h @ ebp-0x1c2
│           ; var int32_t var_1c6h @ ebp-0x1c6
│           ; var int32_t var_1cah @ ebp-0x1ca
│           ; var int32_t var_1fah @ ebp-0x1fa
│           ; var int32_t var_202h @ ebp-0x202
│           ; var int32_t var_212h @ ebp-0x212
│           ; var int32_t var_22ah @ ebp-0x22a
│           ; var int32_t var_23eh @ ebp-0x23e
│           ; var int32_t var_246h @ ebp-0x246
│           ; var int32_t var_26eh @ ebp-0x26e
│           ; var int32_t var_27eh @ ebp-0x27e
│           0x01025884  ~   9a590200a9..   lcall 0x259, 0xa9000259
│           0x0102588b  ~   00ba590200cb   add byte [edx - 0x34fffda7], bh
│           ;-- VirtualProtect:
..
│           0x01025891      59             pop ecx
│           0x01025892      0200           add al, byte [eax]
│           ;-- VirtualFree:
│           0x01025894      da5902         ficomp dword [ecx + 2]
│           0x01025897  ~   00e8           add al, ch
│           ;-- ExitProcess:
..
│           0x01025899      59             pop ecx
│           0x0102589a      0200           add al, byte [eax]
│           0x0102589c      0000           add byte [eax], al
│           0x0102589e      0000           add byte [eax], al
│           ;-- ShellAboutW:
│           0x010258a0      f65902         neg byte [ecx + 2]
│           0x010258a3      0000           add byte [eax], al
│           0x010258a5      0000           add byte [eax], al
│           0x010258a7  ~   00045a         add byte [edx + ebx*2], al
│           ;-- __CxxFrameHandler:
..
│           0x010258aa      0200           add al, byte [eax]
│           0x010258ac      0000           add byte [eax], al
│           0x010258ae      0000           add byte [eax], al
│           ;-- RegOpenKeyExA:
│           0x010258b0      185a02         sbb byte [edx + 2], bl
│           0x010258b3      0000           add byte [eax], al
│           0x010258b5      0000           add byte [eax], al
│           0x010258b7  ~   0028           add byte [eax], ch
│           ;-- SetBkColor:
..
│           0x010258b9      5a             pop edx
│           0x010258ba      0200           add al, byte [eax]
│           0x010258bc      0000           add byte [eax], al
│           0x010258be      0000           add byte [eax], al
│           ;-- GetMenu:
│           0x010258c0      355a020000     xor eax, 0x25a              ; 602
│           0x010258c5      0000           add byte [eax], al
│           0x010258c7      0000           add byte [eax], al
│           0x010258c9      0000           add byte [eax], al
│           0x010258cb      0000           add byte [eax], al
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000040 PE..L.....};..........................

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
  - `KERNEL32.DLL!LoadLibraryA`
  - `KERNEL32.DLL!GetProcAddress`
  - `KERNEL32.DLL!VirtualProtect`
  - `KERNEL32.DLL!VirtualAlloc`
  - `KERNEL32.DLL!VirtualFree`
  - `SHELL32.DLL!ShellAboutW`
  - `MSVCRT.DLL!__CxxFrameHandler`
  - `ADVAPI32.DLL!RegOpenKeyExA`
  - `GDI32.DLL!SetBkColor`
  - `USER32.DLL!GetMenu`
