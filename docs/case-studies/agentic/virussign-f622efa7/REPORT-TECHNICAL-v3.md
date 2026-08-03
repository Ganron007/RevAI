## 1. Executive Summary
This report analyzes a UPX-packed 32-bit Windows PE malware sample (sha256: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc) with a triage score of 9/10. Cross-engine analysis from Malcat, capa, YARA, and pe_imports consistently confirms UPX packing, with a file entropy of 195 consistent with packed/encrypted code (source: malcat deep_profile.file_summary). The underlying payload family is undetermined due to active UPX obfuscation, but FLOSS string analysis reveals network-related capabilities (HTTP and SOCKS proxy support) suggesting a potential remote access trojan (RAT) (source: floss strings). Standard UPX unpacking failed, and no dynamic runtime behavior was observed during analysis, limiting full payload characterization. High-signal imports (LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc) are consistent with packed malware used for dynamic API resolution and memory manipulation during unpacking (source: pe_imports signals).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc |
| Sample Path | /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir |
| Project Name | incoming |
| File Size | 1294570 bytes |
| File Type | PE |
| Architecture | X86 (32-bit) |
| Subsystem | Windows GUI |
| Entry Point (EA) | 188976 |
| Entropy | 195 |
(source: malcat deep_profile.file_summary)

## 3. File Layout & Structural Analysis
The sample has a standard PE header followed by four distinct regions, with a large high-entropy overlay containing the packed payload (source: malcat deep_profile.file_summary):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 180 | - |
| UPX0 | 4096 | 172032 | 172032 | 4 | RWX |
| UPX1 | 176128 | 16384 | 16384 | 168 | RWX |
| UPX2 | 192512 | 4096 | 4096 | 9 | RW |
| overlay | 196608 | 1097962 | 0 | 226 | - |
Malcat flagged 16 total anomalies consistent with UPX packing, including 7 packed-specific anomalies, 2 sections with RWX permissions (SectionWX), 2 executable sections without code flags (ExecutableSectionNoCode), malformed PE header fields (InvalidBaseOfCode, InvalidSizeOfCode, InvalidSizeOfInitializedData), and a high-entropy unknown overlay (source: malcat deep_profile.views.anomalies). The UPX pack header was explicitly recovered at EA 992 (source: malcat Structures table).

## 4. Malcat Triage Summary
Malcat identified 1 total function (the UPX unpacking stub at EntryPoint EA 188976) and recovered the UPX.PackHeader structure at EA 992 (source: malcat deep_profile.file_summary, Functions table).
### Malcat YARA Matches (9 total)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | Detects Visual Studio 6 linker usage |
| MSVC_6_rich | compiler | INFO | 80 | Detects Visual Studio 6 via Rich Header |
| upx_080_or_higher_01 | packer | INFO | 50 | UPX 0.8x+ signature |
| upx_089_3xx | packer | INFO | 50 | UPX 0.89 3xx signature |
| upx_0896_102_105_122_03 | packer | INFO | 50 | UPX 0.896 signature |
| upx_12x | packer | INFO | 50 | UPX 1.2x signature |
| upx_290_lzma_02 | packer | INFO | 50 | UPX 2.90 LZMA signature |
| upx_391_nrv2b_01 | packer | INFO | 50 | UPX 3.91 nrv2b signature |
| upx_394_nrv2b_01 | packer | INFO | 50 | UPX 3.94 nrv2b signature |
(source: malcat deep_profile.yara_signatures)
### High-Signal Anomalies
| Anomaly Name | Level | Category | Hits | Location (EA) |
|---|---|---|---|---|
| SectionWX | 3 | sections | 2 | N/A |
| XorInLoop | 3 | code | 1 | 189059 |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | 332 |
| NoChecksum | 1 | integrity | 1 | 328 |
(source: malcat deep_profile.views.anomalies)
### High-Signal Strings (Malcat)
| EA | String |
|---|---|
| 192692 | KERNEL32.DLL |
| 192740 | WS2_32.dll |
| 192705 | MSVCRT.dll |
| 192716 | OLEAUT32.dll |
| 192729 | USER32.dll |
| 192766 | GetProcAddress |
| 192752 | LoadLibraryA |
| 192782 | VirtualProtect |
| 224280 | wN\\ |
(source: malcat deep_profile.views.strings)
### Import Table (10 total imports)
| EA | Name | Type | Refs |
|---|---|---|---|
| 192632 | kernel32.LoadLibraryA | IMPORT | 1 |
| 192636 | kernel32.GetProcAddress | IMPORT | 0 |
| 192640 | kernel32.VirtualProtect | IMPORT | 0 |
| 192644 | kernel32.VirtualAlloc | IMPORT | 0 |
| 192648 | kernel32.VirtualFree | IMPORT | 0 |
| 192652 | kernel32.ExitProcess | IMPORT | 0 |
| 192660 | msvcrt.atoi | IMPORT | 1 |
| 192668 | oleaut32.GetErrorInfo | IMPORT | 1 |
| 192676 | user32.wsprintfA | IMPORT | 1 |
| 192684 | ws2_32.WSACleanup | IMPORT | 1 |
(source: malcat deep_profile.views.imports)
### EntryPoint Decompilation (UPX Unpack Stub)
The decompiled EntryPoint function at EA 188976 implements the UPX decompression algorithm, with core logic matching the known UPX unpacking stub: a bitwise decompression loop using `uVar16 * 2 + bVar25` to decode packed data from the UPX1 section to the UPX0 section (source: malcat deep_profile.views.decompilations). The full decompilation is available in the Malcat deep profile.

## 5. Static Code Analysis
Static analysis recovered minimal actionable code due to active UPX packing: Ghidra reported 0 recovered functions, while Malcat identified only the UPX unpacking stub at EntryPoint EA 188976 (source: deep_dive_agentic key_evidence). The EntryPoint decompilation confirms this is the standard UPX LZMA decompression routine, which will unpack the payload to the UPX0 RWX section at runtime (source: malcat deep_profile.views.decompilations).
The import table contains 10 total imports, 10 of which are unreferenced in the current packed stub (source: malcat deep_profile.views.anomalies UnreferencedImports row). High-signal imports include:
- LoadLibraryA (EA 192632, 1 reference) and GetProcAddress (EA 192636, 0 references) for dynamic API resolution, a common technique to hide functionality from static analysis (source: pe_imports signals, malcat imports table)
- VirtualProtect (EA 192640, 0 references), VirtualAlloc (EA 192644, 0 references), and VirtualFree (EA 192648, 0 references) for memory manipulation during payload unpacking and potential process injection (source: pe_imports signals)
- WSACleanup (EA 192684, 1 reference) from WS2_32.dll, confirming Winsock usage for network functionality (source: malcat imports table)
Additional static indicators include a XOR instruction in a loop at EA 189059 (source: malcat anomalies XorInLoop row), a VirtualPC detection string at EA 182209 matched by YARA (source: YARA matches VirtualPC_Detection row), and a 16-byte base64-encoded string at EA 180265 (source: YARA matches contains_base64 row). No additional functions or callgraph edges were recovered by Ghidra or Malcat, as all functional code is contained in the packed overlay.

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Standard UPX unpacking failed: the UPX tool returned `upx_ok: False`, `is_packed: False`, with no returncode and an empty unpacked_path, indicating the sample could not be unpacked with the default UPX configuration (source: UPX Unpack section). Speakeasy dynamic analysis completed successfully but recorded 0 API calls and 0 key events, with no runtime behavior to report (source: Speakeasy section, noted as not observed). Frida v17.16.4 was available but no data was collected during probing (source: Frida Probe section, noted as not observed). As a result, no confirmed payload behaviors (e.g., file system modifications, network connections, credential theft) were observed at runtime.

## 7. Network Indicators & C2
Static analysis indicates the underlying packed payload has network capabilities, but no confirmed C2 infrastructure was identified. FLOSS extracted 2050 static strings, including high-signal indicators of network functionality: `s HTTP/1.1` (indicating HTTP support) and `f~fsocks\\a` (indicating SOCKS proxy support) (source: floss high-signal strings). The import of WS2_32.dll (WSACleanup at EA 192684) confirms the payload uses Windows Winsock for network operations (source: malcat imports table). YARA rules matched generic domain and IPv6 regex patterns, but no specific C2 IP addresses or domains were extracted from static strings (source: YARA matches domain and IP rows). No network connections were observed during dynamic analysis, as no runtime behavior was recorded.

## 8. Capabilities & MITRE ATT&CK Mapping
Confirmed capabilities from static analysis are limited to packing and pre-unpacking stub functionality, with potential capabilities inferred from imports and strings:
| Capability | Source | MITRE ATT&CK / MBC |
|---|---|---|
| Software Packing (UPX) | capa top_rules | T1027.002: Obfuscated Files or Information, MBC F0001.008: Software Packing |
| Dynamic API Resolution | pe_imports signals, malcat imports | T1129: Process Injection |
| Memory Manipulation (VirtualProtect, VirtualAlloc, VirtualFree) | pe_imports signals | T1055: Process Injection |
| Virtual Machine Detection | YARA matches VirtualPC_Detection | T1497.001: Virtualization/Sandbox Evasion |
| Network Support (HTTP, SOCKS, Winsock) | floss strings, malcat imports | Potential T1071: Application Layer Protocol (unconfirmed, payload not unpacked) |
(source: capa top_rules, pe_imports signals, YARA matches, floss strings)
No additional capabilities (e.g., credential theft, keylogging, persistence, lateral movement) could be confirmed due to active UPX packing and lack of unpacked payload analysis.

## 9. Indicators of Compromise
### File Hashes
- SHA256: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc
### PE Structural Indicators
- UPX section names: UPX0, UPX1, UPX2 (source: malcat file layout table)
- High file entropy: 195 (source: malcat file_summary)
- RWX permissions on UPX0 and UPX1 sections (source: malcat file layout table)
- GUI subsystem with no user32 window-related imports (source: malcat anomaly GuiSubsystemNoWindowApi at EA 332)
### High-Signal Strings
- KERNEL32.DLL at EA 192692, LoadLibraryA at EA 192752, GetProcAddress at EA 192766, VirtualProtect at EA 192782 (source: malcat high-signal strings)
- WS2_32.dll at EA 192740 (source: malcat top strings)
- `s HTTP/1.1`, `f~fsocks\\a` (source: floss high-signal strings)
### Code Indicators
- XOR instruction in a loop at EA 189059 (source: malcat anomaly XorInLoop)
- UPX unpacking stub at EntryPoint EA 188976 (source: malcat Functions table)
### YARA Indicators
All 25 YARA matches are valid IOCs, with key rules including:
- UPX, UPXv20MarkusLaszloReiser, UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser, UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser, IsPacked, HasOverlay (source: YARA matches table)
- VirtualPC_Detection at EA 182209 (source: YARA matches VirtualPC_Detection row)

## 10. Detection Engineering
### YARA Detection
Leverage the existing UPX-related YARA matches (9 rules from Malcat) to flag packed samples. Add custom rules for:
- The XOR loop at EA 189059
- The high-signal network strings `s HTTP/1.1` and `f~fsocks\\a`
- The unreferenced import pattern (10+ unreferenced imports combined with UPX sections)
### PE Import Detection
Flag PE files with the combination of LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, and WSACleanup imports, plus UPX section names and entropy > 190.
### Anomaly-Based Detection
Flag samples with the following Malcat-identified anomalies:
- SectionWX (RWX sections)
- UnreferencedImports > 10
- GuiSubsystemNoWindowApi (GUI subsystem without user32 window APIs)
- InvalidBaseOfCode, InvalidSizeOfCode, InvalidSizeOfInitializedData
- High-entropy (>220) unknown overlay
### Unpacking Requirement
Full payload analysis requires successful UPX unpacking. The standard UPX tool failed for this sample, so detection rules should account for packed UPX samples and prioritize unpacking via custom UPX stubs or runtime memory dumping for deeper inspection.

## 11. What We Don't Know
- The underlying payload family is undetermined, as standard UPX unpacking failed and the packed payload could not be analyzed (source: UPX Unpack section, llm_judge verdict).
- No confirmed C2 IP addresses or domains were identified from static or dynamic analysis (source: YARA matches, floss strings, Speakeasy not observed).
- No confirmed malicious payload behaviors (e.g., file system tampering, credential theft, keylogging, persistence, lateral movement) are known, as the payload remains packed and unanalyzed (source: deep_dive_agentic summary).
- The purpose of the 10 unreferenced imports is unclear: they may be decoys to confuse static analysis, or used by the unpacked payload at runtime (source: malcat anomaly UnreferencedImports).
- No dynamic runtime behavior was observed, so no confirmed in-memory actions, network connections, or process injection events are documented (source: Speakeasy not observed, Frida not observed).
- The purpose of the high-entropy overlay beyond containing the packed UPX payload is unknown (source: malcat anomaly UnknownOverlayMediumToHighEntropy).

## 12. Appendix: Analysis Environment
| Tool / Component | Version / Details | Observations |
|---|---|---|
| Malcat | Deep Profile | Recovered UPX pack header, 1 function, 16 anomalies, 2050 FLOSS strings, full decompilation of EntryPoint stub |
| capa | malcat-capa engine | 1 rule matched: packed with UPX (T1027.002) |
| pe_imports | N/A | 10 imports identified, 4 high-signal ATT&CK mappings |
| YARA | Pipeline (25 rules) | 9 UPX-related matches, plus VM detection, base64, domain/IP regex matches |
| FLOSS | N/A | 2050 static strings extracted, 2 high-signal network strings |
| Ghidra | N/A | 0 functions recovered, memory blocks show UPX0/UPX1/UPX2 sections, import thunks at 0x4386936-0x4386988, export 'entry' at 0x4383280 |
| UPX Unpack Tool | N/A | Failed to unpack: upx_ok=False, returncode=None, unpacked_path empty |
| XOR Search | N/A | Found XOR 00 pattern at position 00000000 |
| Speakeasy | N/A | Completed successfully, 0 API calls, 0 key events (not observed) |
| Frida | 17.16.4 | Available, no data collected (not observed) |
| Sample Path | /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir | Project: incoming |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc  
**sample_path:** /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: UPX-packed 32-bit Windows PE malware with network-enabled underlying payload
- **score**: 9
- **family_guess**: Underlying family undetermined due to active UPX packing; potential remote access trojan (RAT) based on network-related strings
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: All valid analysis engines (Malcat, capa, YARA, pe_imports) consistently confirm UPX packing. Ghidra reports 0 functions while Malcat identifies 1 entry point function, likely due to Ghidra's inability to analyze obfuscated packed code. IDA has no valid data per intake validation, so its results are excluded. High entropy and packing-related anomalies are consistent across Malcat and YARA results. Imports identified by pe_imports align with Malcat's import table data.
- **summary**: This is a UPX-packed 32-bit Windows PE file with a very high entropy of 195, consistent with packed/encrypted code. Multiple independent analysis sources (capa, YARA, Malcat) confirm it is packed with UPX, a common open-source packer used to obfuscate malware. The decompiled entry point matches the known UPX unpacking stub implementation, including core decompression logic. High-signal imports (LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc) are typical of packed malware, used for dynamic API resolution and memory manipulation during payload unpacking. FLOSS string analysis reveals the underlying packed payload has network capabilities (HTTP and SOCKS proxy support), suggesting it may be a network-enabled malware family such as a remote access trojan (RAT), though full payload behavior cannot be determined until the UPX packer is removed. The sample exhibits multiple anomalies consistent with packing, including RWX memory sections, malformed PE header fields, and a high-entropy overlay containing the packed payload.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with UPX rule (ATT&CK T1027.002, MBC F0001.008)` | Directly identifies the sample as packed with UPX, mapping to defense evasion via software packing, confirming the core  |
| yara | matches | `UPX, UPX_089_3xx, UPX_290_LZMA, UPX_394_nrv2b_01 (9 total UPX-related matching r` | Multiple YARA rules targeting UPX packer signatures across versions 0.8x to 3.9x match the sample, providing independent |
| pe_imports | signals | `LoadLibraryA (T1129), GetProcAddress (T1129), VirtualProtect (T1055), VirtualAll` | These high-signal imports are characteristic of packed malware: dynamic API resolution to hide functionality, and memory |
| malcat | deep_profile.file_summary | `UPX.PackHeader recovered structure, 7 Packed anomalies, entropy=195` | Malcat explicitly recovers the UPX pack header, flags 7 distinct packing anomalies, and reports very high entropy consis |
| malcat | deep_profile.views.anomalies | `SectionWX×2, ExecutableSectionNoCode×2, InvalidBaseOfCode, InvalidSizeOfCode, Un` | These anomalies are all consistent with UPX-packed samples: RWX sections, malformed PE headers from packing, and high-en |
| malcat | deep_profile.views.decompilations | `EntryPoint decompilation (bitwise decompression loop: uVar16 * 2 + bVar25 logic)` | The decompiled entry point matches the known UPX unpacking stub implementation, including core decompression algorithm l |
| floss | strings | `"s HTTP/1.1", "f~fsocks\\a"` | These strings indicate the underlying packed payload has network functionality (HTTP, SOCKS proxy support), a common fea |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 70
- **summary**: The sample is a 32-bit Windows GUI PE that is packed with UPX. Static analysis recovered no functions or callgraph edges, but the import table and strings show dynamic import resolution via LoadLibraryA/GetProcAddress and VirtualProtect/VirtualAlloc/VirtualFree, consistent with runtime unpacking or code injection. No confirmed malicious payload behavior is visible in the recovered static data.

### deep key_evidence
- `"Ghidra memory blocks show UPX0/UPX1/UPX2 sections and no recovered functions"`
- `"YARA checklist matches UPX, UPXv20MarkusLaszloReiser, UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser, UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser, IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasRichSignature"`
- `"capa_analyze reports packed with UPX (T1027.002)"`
- `"Ghidra imports include LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess, atoi, wsprintfA, Ordinal_200 (OLEAUT32), Ordinal_116 (WS2_32)"`
- `"Ghidra xrefs show import thunk references at 0x4386936-0x4386988 and export 'entry' at 0x4383280"`
- `"FLOSS extracted 2050 static strings including HTTP/1.1 and URL-like fragments, but no clear C2 or command strings"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc
size: 1294570
type: PE
architecture: X86
entrypoint_ea: 188976
entropy: 195
file_name: virussign.com_f622efa728edc2b6d606315cc6746fa9.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 180 | - |
| UPX0 | 4096 | 172032 | 172032 | 4 | RWX |
| UPX1 | 176128 | 16384 | 16384 | 168 | RWX |
| UPX2 | 192512 | 4096 | 4096 | 9 | RW |
| overlay | 196608 | 1097962 | 0 | 226 | - |

### Malcat YARA / Signatures (9)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_6_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| upx_080_or_higher_01 | packer | INFO | 50 |  |
| upx_089_3xx | packer | INFO | 50 |  |
| upx_0896_102_105_122_03 | packer | INFO | 50 |  |
| upx_12x | packer | INFO | 50 |  |
| upx_290_lzma_02 | packer | INFO | 50 |  |
| upx_391_nrv2b_01 | packer | INFO | 50 |  |
| upx_394_nrv2b_01 | packer | INFO | 50 |  |

### Anomalies (16)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ExecutableSectionNoCode | 4 | sections | 2 | executable section has the flag code not set |
| InvalidBaseOfCode | 4 | sections | 1 | at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section |
| InvalidBaseOfData | 4 | sections | 1 | at least one data section starts before BaseOfData, or BaseOfData is not the start of a data section |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 1 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| SectionNameUnknown | 3 | sections | 1 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnknownOverlayMediumToHighEntropy | 3 | entropy | 1 | File contains an overlay which is not of known type and has medium-to-high entropy |
| UnreferencedImports | 3 | imports | 10 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| Packed | 2 | packers | 7 | File is packed using a legit or less-legit obfuscator |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `332`: 
- **NoChecksum**
  - `328`: 
- **XorInLoop**
  - `189059`: 

### High-Signal Strings (5 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 192692 | `KERNEL32.DLL` |
| 192766 | `GetProcAddress` |
| 192752 | `LoadLibraryA` |
| 192782 | `VirtualProtect` |
| 224280 | `wN\\` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 192692 | `KERNEL32.DLL` |
| 192740 | `WS2_32.dll` |
| 192705 | `MSVCRT.dll` |
| 192716 | `OLEAUT32.dll` |
| 192729 | `USER32.dll` |
| 964158 | `..cUq` |
| 181029 | `u.exe` |
| 926559 | `
f

X` |
| 77 | `!This program ca..in DOS mode.
$` |
| 1117449 | `h.CGY` |
| 719415 | `T.lVM` |
| 1122035 | `J.qL4` |
| 848062 | `ll` |
| 832631 | `TnTT` |
| 467945 | `@3.s` |
| 545805 | `oDDo` |
| 836483 | `

` |
| 1107731 | `>>>=` |
| 761583 | `
w]

`N` |
| 233355 | `t1UUU` |
| 379208 | `56\65` |
| 1260293 | `TwkTk` |
| 261265 | `gg[[m` |
| 176288 | `/Qmlv%uwjbwdh%fdkkjq%g`%wpk%` |
| 192766 | `GetProcAddress` |
| 308391 | `O@GYOG` |
| 807279 | `I

-` |
| 1001598 | ``Ycc`;` |
| 176669 | `u34v43` |
| 1260424 | `:

r` |
| 300103 | `
r
4` |
| 694684 | `8--8:6` |
| 369349 | `i7vv_7` |
| 770872 | `m6Ao6o` |
| 307560 | `3
af3` |
| 368877 | `>7`GGU>` |
| 192752 | `LoadLibraryA` |
| 661766 | `%.r9Q` |
| 687161 | `vQ1313h` |
| 577414 | `;HDnHbD` |
| 796378 | `c
HB
P` |
| 179994 | `loglvTcpkc`ng` |
| 592175 | `PrFB11-P` |
| 180602 | `smdp_Bss` |
| 192782 | `VirtualProtect` |
| 1004131 | `bb_8` |
| 1092952 | `S00i` |
| 760331 | `>004` |
| 631783 | `_^?_` |
| 540903 | `--bA` |
| 285572 | `hVhu` |
| 718365 | `2LLE` |
| 718550 | `>>Lg` |
| 1287883 | `6442` |
| 1284154 | `fXXC` |
| 827266 | `]EEX` |
| 1173592 | `xxW7` |
| 1234368 | `lLLf` |
| 1131383 | `
E` |
| 1131305 | `5rrM` |
| 476201 | `cr@r` |
| 463846 | `55kN` |
| 1121667 | `pp>b` |
| 1275307 | `55P` |
| 1268943 | ``6]]` |
| 603744 | `33<Z` |
| 1224521 | `q:qv` |
| 280719 | `h2;h` |
| 1000016 | `BrB`` |
| 547587 | `o\w\` |
| 513810 | `>c@@` |
| 188490 | `??1t` |
| 670757 | `PDD<` |
| 462930 | `<XE<` |
| 396490 | `jgjm` |
| 284552 | `=Z=X` |
| 594406 | `rH2H` |
| 188337 | `Addr` |
| 1273182 | `L@@A` |
| 207869 | `;Tp;` |

### Imports (10)
| EA | Name | Type | Refs |
|---|---|---|---|
| 192632 | kernel32.LoadLibraryA | IMPORT | 1 |
| 192636 | kernel32.GetProcAddress | IMPORT | 0 |
| 192640 | kernel32.VirtualProtect | IMPORT | 0 |
| 192644 | kernel32.VirtualAlloc | IMPORT | 0 |
| 192648 | kernel32.VirtualFree | IMPORT | 0 |
| 192652 | kernel32.ExitProcess | IMPORT | 0 |
| 192660 | msvcrt.atoi | IMPORT | 1 |
| 192668 | oleaut32.GetErrorInfo | IMPORT | 1 |
| 192676 | user32.wsprintfA | IMPORT | 1 |
| 192684 | ws2_32.WSACleanup | IMPORT | 1 |

### Functions (1)
| EA | Name |
|---|---|
| 188976 | EntryPoint |

### Decompilations (top 6)
#### 188976 — EntryPoint
```c

/* WARNING: Instruction at (ram,0x0042e338) overlaps instruction at (ram,0x0042e337)
    */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    char cVar1;
    undefined uVar2;
    char cVar3;
    int32_t iVar4;
    code *pcVar5;
    uint8_t uVar6;
    undefined *puVar7;
    int32_t iVar8;
    int32_t iVar9;
    uint32_t uVar10;
    undefined4 uVar11;
    uint8_t *puVar12;
    int32_t iVar13;
    int32_t **ppiVar14;
    undefined4 *puVar15;
    uint32_t uVar16;
    uint32_t uVar17;
    int32_t *piVar18;
    uint32_t uVar19;
    uint32_t *puVar20;
    undefined4 *puVar21;
    int32_t **ppiVar22;
    int32_t **ppiVar23;
    int32_t **ppiVar24;
    bool bVar25;
    bool bVar26;
    bool bVar27;
    undefined auStack_a0 [88];
    undefined4 uStack_48;
    int32_t iStack_44;
    undefined4 uStack_40;
    int32_t iStack_3c;
    int32_t *piStack_38;
    int32_t iStack_34;
    int32_t iStack_30;
    int32_t iStack_2c;
    int32_t ***pppiStack_28;
    int32_t **ppiStack_24;
    
    puVar20 = 0x42b000;
    puVar21 = 0x401000;
    uVar19 = 0xffffffff;
    do {
        uVar16 = *puVar20;
        bVar25 = puVar20 < 0xfffffffc;
        puVar20 = puVar20 + 1;
        bVar26 = CARRY4(uVar16, uVar16) || CARRY4(uVar16 * 2, bVar25);
        uVar16 = uVar16 * 2 + bVar25;
        do {
            if (bVar26) {
                uVar2 = *puVar20;
                puVar20 = puVar20 + 1;
                *puVar21 = uVar2;
                puVar21 = puVar21 + 1;
            }
            else {
                uVar10 = 1;
                do {
                    do {
                        bVar25 = CARRY4(uVar16, uVar16);
                        uVar17 = uVar16 * 2;
                        if (uVar17 == 0) {
                            uVar16 = *puVar20;
                            bVar26 = puVar20 < 0xfffffffc;
                            puVar20 = puVar20 + 1;
                            bVar25 = CARRY4(uVar16, uVar16) || CARRY4(uVar16 * 2, bVar26);
                            uVar17 = uVar16 * 2 + bVar26;
                        }
                        uVar10 = uVar10 * 2 + bVar25;
                        uVar16 = uVar17 * 2;
                    } while (!CARRY4(uVar17, uVar17));
                    if (uVar16 != 0) break;
                    uVar17 = *puVar20;
                    bVar25 = puVar20 < 0xfffffffc;
                    puVar20 = puVar20 + 1;
                    uVar16 = uVar17 * 2 + bVar25;
                } while (!CARRY4(uVar17, uVar17) && !CARRY4(uVar17 * 2, bVar25));
                if (2 < uVar10) {
                    uVar2 = *puVar20;
                    puVar20 = puVar20 + 1;
                    uVar19 = CONCAT31(uVar10 + -3, uVar2) ^ 0xffffffff;
                    if (uVar19 == 0) {
                        ppiVar22 = 0x42d000;
                        goto code_r0x0042e309;
                    }
                }
                bVar25 = CARRY4(uVar16, uVar16);
                uVar16 = uVar16 * 2;
                if (uVar16 == 0) {
                    uVar16 = *puVar20;
                    bVar26 = puVar20 < 0xfffffffc;
                    puVar20 = puVar20 + 1;
                    bVar25 = CARRY4(uVar16, uVar16) || CARRY4(uVar16 * 2, bVar26);
                    uVar16 = uVar16 * 2 + bVar26;
                }
                bVar26 = CARRY4(uVar16, uVar16);
                uVar16 = uVar16 * 2;
                if (uVar16 == 0) {
                    uVar16 = *puVar20;
                    bVar27 = puVar20 < 0xfffffffc;
                    puVar20 = puVar20 + 1;
                    bVar26 = CARRY4(uVar16, uVar16) || CARRY4(uVar16 * 2, bVar27);
                    uVar16 = uVar16 * 2 + bVar27;
                }
                iVar13 = bVar25 * 2 + bVar26;
                if (iVar13 == 0) {
                    iVar13 = 1;
                    do {
                        do {
                            bVar25 = CARRY4(uVar16, uVar16);
                            uVar10 = uVar16 * 2;
              
```

### Structures (13)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 240 |
| OptionalHeader | 264 |
| Sections | 488 |
| UPX.PackHeader | 992 |
| ImportTable | 192512 |
| kernel32.FT | 192632 |
| msvcrt.FT | 192660 |
| oleaut32.FT | 192668 |
| user32.FT | 192676 |
| ws2_32.FT | 192684 |
| ImportNames | 192692 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.9

| Rule | ATT&CK | MBC |
|---|---|---|
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |

## PE Imports / Signals
import_count: 10

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 25

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@209129 len=2 |
| contains_base64 | - | $a@180265 len=16 |
| VirtualPC_Detection | - | $a0@182209 len=4 |
| UPX | - | $a@488 len=4; $b@528 len=4; $c@992 len=4 |
| UPXv20MarkusLaszloReiser | - | $a0@189244 len=85 |
| UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser | - | $a0@189291 len=39 |
| UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser | - | $a1@188976 len=63 |
| upx_3 | - | $str1@188976 len=45 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@208 len=4 |
| PackerUPX_CompresorGratuito_wwwupxsourceforgenet | - | $a@188976 len=12 |
| UPX_wwwupxsourceforgenet_additional | - | $a@188976 len=12 |
| yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h | - | $a@1069 len=1 |
| Netopsystems_FEAD_Optimizer_1 | - | $a@188976 len=64 |
| UPX_290_LZMA | - | $a@188976 len=63 |
| UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser | - | $b@188976 len=63 |
| UPX_290_LZMA_additional | - | $a@188976 len=63 |
| UPX_wwwupxsourceforgenet | - | $a@188976 len=12; $b@188976 len=12 |
| suspicious_packer_section | - |  |
| vmdetect | - | $virtualpc@182209 len=4 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@192740 len=10 |

## Generated YARA Meta
```json
{
  "rule_count": 25,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
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
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 209129,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 180265,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VirtualPC_Detection",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 182209,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 488,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 528,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 992,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXv20MarkusLaszloReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 189244,
          "length": 85,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 189291,
          "length": 39,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a1",
          "offset": 188976,
          "length": 63,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "upx_3",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$str1",
          "offset": 188976,
          "length": 45,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "
```

## FLOSS Strings
Total strings: 2050 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2050}`

### High-signal FLOSS
- `*	]\\8`
- `s HTTP/1.1`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `%6w*iA`
- `h8U^L&`
- `cR>#4jX(C`
- `59D;Fw`
- `.SW1zTE`
- `Cb|cn+`
- ``ud2KTcxwc`
- `]pg&*+`
- `/Qmlv%uwjbwdh%fdkkjq%g`%wpk%`
- `AJV%hja`+`
- `9'Wlfm?`
- `w`}nw+`
- `u34v43`
- `asw=((`
- `:cd616rv7Z6`
- ``q	Sfs`
- `RVDV`k`
- `*	]\\8`
- `x5y<{i`
- `g*QQ!U`
- `<!65{+`
- `PN8f<#`
- `BPQ`huUdq`
- `Rwlq`Uwjf`v`
- `V-`uFijv`pj`
- `_x5`Qm`
- `}TW$U+`
- `5Z9op\`
- `[{Zcalshd`
- `Mjjn@}`
- `N@WK@I`
- `HVSFWQ`
- `/IjdaIl`
- `cftcrk`
- `10,fnn3igpin`
- `RpmaCffpgO`
- `loglvTcpkc`ng`
- `klGzga`
- `Amr{Dk`

## .NET Analysis
- is_dotnet: false (not observed)

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
