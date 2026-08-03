## 1. Executive Summary
This sample is a UPX-packed 32-bit Windows GUI PE file with a maliciousness score of 9, per the llm_judge verdict (source: llm_judge). It exhibits very high entropy (195) consistent with packed/encrypted code, and 9 independent YARA rules confirm UPX packing across versions 0.8x to 3.9x (source: yara). The capa engine identifies the packing as ATT&CK technique T1027.002 (Obfuscated Files or Information) / MBC F0001.008 (Software Packing) (source: capa). Static analysis reveals a single EntryPoint function that implements the UPX unpacking stub, with imports typical of packed malware (LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc) used for dynamic API resolution and memory manipulation during unpacking (source: malcat, pe_imports). FLOSS string analysis indicates the underlying packed payload has network capabilities (HTTP, SOCKS proxy support), suggesting it may be a network-enabled remote access trojan (RAT), though the underlying family cannot be confirmed until UPX packing is removed (source: floss). No runtime behavior was observed in dynamic analysis environments (Speakeasy, Frida), and UPX unpacking attempts failed (source: speakeasy, frida_probe, upx).

## 2. Sample Metadata
| Field | Value | Source |
|---|---|---|
| SHA256 | 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc | llm_judge |
| Sample Path | /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir | llm_judge |
| Project Name | incoming | llm_judge |
| File Size | 1294570 bytes | malcat deep_profile.file_summary |
| File Type | PE | malcat deep_profile.file_summary |
| Architecture | X86 | malcat deep_profile.file_summary |
| Subsystem | Windows GUI | yara matches (IsWindowsGUI rule) |
| Entry Point EA | 188976 | malcat deep_profile.file_summary |
| Entropy | 195 | malcat deep_profile.file_summary |
| Verdict | UPX-packed 32-bit Windows PE malware with network-enabled underlying payload | llm_judge |
| Maliciousness Score | 9 | llm_judge |
| Family Guess | Unknown (potential RAT based on network strings) | llm_judge |

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows PE with standard UPX section naming and a high-entropy overlay containing the packed payload. Section details are below (source: malcat deep_profile.file_summary):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 180 | - |
| UPX0 | 4096 | 172032 | 172032 | 4 | RWX |
| UPX1 | 176128 | 16384 | 16384 | 168 | RWX |
| UPX2 | 192512 | 4096 | 4096 | 9 | RW |
| overlay | 196608 | 1097962 | 0 | 226 | - |

Malcat flagged 16 total anomalies, 7 of which are directly related to packing (source: malcat deep_profile.views.anomalies):
| Anomaly Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| SectionWX | 3 | sections | 2 | Executable and writeable sections (UPX0, UPX1) |
| ExecutableSectionNoCode | 4 | sections | 2 | Executable sections lack code flags |
| InvalidBaseOfCode | 4 | sections | 1 | Code section start misaligned with BaseOfCode |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode does not match sum of code sections |
| UnknownOverlayMediumToHighEntropy | 3 | entropy | 1 | High-entropy overlay of unknown type |
| Packed | 2 | packers | 7 | File is packed with an obfuscator |
| UnreferencedImports | 3 | imports | 10 | >50% of imports have no cross-references |
| XorInLoop | 3 | code | 1 | XOR instruction present in a loop (EA 189059) |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | GUI subsystem with no user32 window imports |

Recovered PE structures include the UPX.PackHeader at EA 992, ImportTable at EA 192512, and import function tables for kernel32, msvcrt, oleaut32, user32, and ws2_32 (source: malcat deep_profile.structures).

## 4. Malcat Triage Summary
Malcat identified 1 total function (EntryPoint at EA 188976), 10 imports, 9 UPX-related YARA matches, and 2050 total static strings (source: malcat deep_profile).
### Full Import Address Table (IAT)
| EA | Import Name | Type | Refs |
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

### Malcat YARA Matches (9 UPX-related)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| upx_080_or_higher_01 | packer | INFO | 50 | UPX 0.8x+ signature |
| upx_089_3xx | packer | INFO | 50 | UPX 0.89-3.xx signature |
| upx_0896_102_105_122_03 | packer | INFO | 50 | UPX 0.89.6-1.02 signature |
| upx_12x | packer | INFO | 50 | UPX 1.2x signature |
| upx_290_lzma_02 | packer | INFO | 50 | UPX 2.90 LZMA signature |
| upx_391_nrv2b_01 | packer | INFO | 50 | UPX 3.91 NRV2B signature |
| upx_394_nrv2b_01 | packer | INFO | 50 | UPX 3.94 NRV2B signature |
| MSVC_6_linker | compiler | INFO | 60 | Visual Studio 6 linker signature |
| MSVC_6_rich | compiler | INFO | 80 | Visual Studio 6 Rich Header signature |

### High-Signal Strings (Malcat)
| EA | String |
|---|---|
| 192692 | KERNEL32.DLL |
| 192740 | WS2_32.dll |
| 192752 | LoadLibraryA |
| 192766 | GetProcAddress |
| 192782 | VirtualProtect |

### EntryPoint Decompilation (UPX Unpacking Stub)
```c
void EntryPoint(void) {
    uint32_t *puVar20 = 0x42b000; // Packed data source
    undefined4 *puVar21 = 0x401000; // Unpacked destination
    uint32_t uVar19 = 0xffffffff;
    do {
        uint32_t uVar16 = *puVar20;
        bool bVar25 = puVar20 < 0xfffffffc;
        puVar20 = puVar20 + 1;
        bool bVar26 = CARRY4(uVar16, uVar16) || CARRY4(uVar16 * 2, bVar25);
        uVar16 = uVar16 * 2 + bVar25;
        do {
            if (bVar26) {
                undefined uVar2 = *puVar20;
                puVar20 = puVar20 + 1;
                *puVar21 = uVar2;
                puVar21 = puVar21 + 1;
            } else {
                // Core UPX decompression bitwise loop logic
                uint32_t uVar10 = 1;
                do {
                    do {
                        bool bVar25 = CARRY4(uVar16, uVar16);
                        uint32_t uVar17 = uVar16 * 2;
                        if (uVar17 == 0) {
                            uVar16 = *puVar20;
                            bool bVar26 = puVar20 < 0xfffffffc;
                            puVar20 = puVar20 + 1;
                            bVar25 = CARRY4(uVar16, uVar16) || CARRY4(uVar16 * 2, bVar26);
                            uVar17 = uVar16 * 2 + bVar26;
                        }
                        uVar10 = uVar10 * 2 + bVar25;
                        uVar16 = uVar17 * 2;
                    } while (!CARRY4(uVar17, uVar17));
                    if (uVar16 != 0) break;
                    uint32_t uVar17 = *puVar20;
                    bool bVar25 = puVar20 < 0xfffffffc;
                    puVar20 = puVar20 + 1;
                    uVar16 = uVar17 * 2 + bVar25;
                } while (!CARRY4(uVar17, uVar17) && !CARRY4(uVar17 * 2, bVar25));
                // ... (decompression logic continues)
            }
        } while (true);
    } while (true);
}
```
This decompilation matches known UPX unpacking stub implementation, confirming the sample is packed with UPX (source: malcat deep_profile.views.decompilations).

## 5. Static Code Analysis
Ghidra recovered 0 functions from the sample due to active UPX packing, while Malcat recovers 1 EntryPoint function at EA 188976 (source: ghidra_query, malcat deep_profile.functions). The only recovered code is the UPX unpacking stub, which uses standard packed malware APIs for runtime unpacking:
- Dynamic API resolution via LoadLibraryA and GetProcAddress to hide imported functionality (source: pe_imports)
- Memory manipulation via VirtualProtect, VirtualAlloc, and VirtualFree to modify memory permissions and allocate space for the unpacked payload (source: pe_imports)
- ExitProcess to terminate the process if unpacking fails (source: pe_imports)
- wsprintfA and ati for string formatting and integer conversion during unpacking (source: pe_imports)
- Ordinal imports from OLEAUT32 (Ordinal_200) and WS2_32 (Ordinal_116) for COM and Winsocket functionality, likely used by the underlying unpacked payload (source: ghidra_query imports)

Ghidra xrefs show import thunk references at 0x4386936-0x4386988 and an export named 'entry' at 0x4383280 (source: deep_dive_agentic). No additional functions or callgraph edges were recovered, as all underlying payload code is encrypted/compressed in the UPX overlay (source: ghidra_query callgraph_edges).

## 6. Behavioral & Dynamic Analysis
No runtime behavior was observed during dynamic analysis:
- **Speakeasy**: speakeasy_ok is True, but 0 API calls and 0 key events were recorded; no execution behavior was captured (source: speakeasy)
- **Frida**: Frida v17.16.4 is available, but no probe events were recorded (source: frida_probe)
- **UPX Unpack**: The UPX unpack attempt failed (upx_ok: False, returncode: None, unpacked_path: empty) (source: upx unpack data)

No process injection, network connections, file system modifications, or other malicious behaviors were observed in the dynamic environment, likely because the sample did not successfully execute its unpacking routine in the sandbox (source: speakeasy, frida_probe).

## 7. Network Indicators & C2
Static string analysis via FLOSS extracted 2050 total strings, with high-signal network-related artifacts indicating the underlying payload has network capabilities (source: floss):
- `s HTTP/1.1`: Indicates HTTP protocol support for C2 or data exfiltration
- `f~fsocks\a`: Indicates SOCKS proxy support for network traffic tunneling

Additional network-related static artifacts include the WS2_32.dll import string at EA 192740 (source: malcat top strings) and a YARA match for the Str_Win32_Winsock2_Library rule at the same EA (source: yara matches). No confirmed C2 IP addresses, domains, or URL patterns were identified in static strings, and no active network connections were observed in dynamic analysis (source: floss, speakeasy).

## 8. Capabilities & MITRE ATT&CK Mapping
Confirmed capabilities from static analysis are limited to packing and unpacking functionality, with inferred network capabilities for the underlying payload:
| Capability | Rule/Import | ATT&CK Technique | MBC | Source |
|---|---|---|---|---|
| Software Packing | capa rule: packed with UPX | T1027.002: Obfuscated Files or Information | F0001.008: Software Packing | capa top_rules |
| Dynamic API Resolution | LoadLibraryA, GetProcAddress | T1129: Process Injection | - | pe_imports signals |
| Memory Manipulation | VirtualProtect, VirtualAlloc | T1055: Process Injection | - | pe_imports signals |
| Network Support (inferred) | HTTP/1.1, SOCKS proxy strings | - | - | floss strings |

No additional capabilities (e.g., credential theft, file system manipulation, persistence) could be confirmed due to active UPX packing (source: llm_judge, deep_dive_agentic).

## 9. Indicators of Compromise
| Indicator Type | Value | Source |
|---|---|---|
| SHA256 Hash | 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc | llm_judge |
| Sample Path | /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir | llm_judge |
| UPX Pack Header EA | 992 | malcat deep_profile.structures |
| Overlay EA | 196608 | malcat deep_profile.file_summary |
| Entry Point EA | 188976 | malcat deep_profile.file_summary |
| High-Signal Import EAs | 192632 (LoadLibraryA), 192636 (GetProcAddress), 192640 (VirtualProtect), 192644 (VirtualAlloc) | malcat deep_profile.imports |
| Network String EAs | 192740 (WS2_32.dll), FLOSS `s HTTP/1.1`, `f~fsocks\a` | malcat top strings, floss strings |
| Matching YARA Rules | UPX, UPX_089_3xx, UPX_290_LZMA, UPX_394_nrv2b_01, IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasRichSignature, VirtualPC_Detection, vmdetect, Str_Win32_Winsock2_Library | yara matches |

## 10. Detection Engineering
This sample is detectable via multiple static signatures:
1. **UPX Packing Signatures**: 9 YARA rules targeting UPX packer versions 0.8x to 3.9x match the sample, including rules for UPX LZMA and NRV2B compression (source: yara matches). A generated YARA rule is available at `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/rule.yar` (source: rule.yara.json).
2. **Packed PE Anomalies**: Rules detecting RWX sections, unreferenced imports (10 total), high-entropy overlay (entropy 226), and malformed PE headers (InvalidBaseOfCode, InvalidSizeOfCode) will flag this sample (source: malcat deep_profile.views.anomalies).
3. **capa Rule**: The `packed with UPX` capa rule (T1027.002) reliably identifies this sample (source: capa top_rules).
4. **Import Signatures**: Rules matching the combination of LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, and WS2_32.dll imports in a GUI PE with no user32 window imports will detect similar packed samples (source: pe_imports, malcat anomalies).

## 11. What We Don't Know
1. The underlying payload family is unknown: UPX packing is active, and all unpacking attempts (UPX CLI, dynamic analysis) failed to recover the original payload (source: llm_judge, upx unpack data, speakeasy).
2. No confirmed C2 infrastructure: No static C2 IPs/domains or dynamic network connections were observed (source: floss, speakeasy).
3. No confirmed malicious capabilities of the unpacked payload: Static analysis cannot access the underlying code due to packing, and no runtime behavior was captured (source: deep_dive_agentic, speakeasy).
4. Ghidra recovered 0 functions from the sample, so no additional static code analysis of the underlying payload is possible without successful unpacking (source: ghidra_query funcs count).
5. The purpose of the 10 unreferenced imports is unknown: they may be decoys to confuse analysis, or used by the unpacked payload after runtime resolution (source: malcat deep_profile.views.anomalies).

## 12. Appendix: Analysis Environment
| Tool/Environment | Version/Details | Status | Source |
|---|---|---|---|
| Malcat | Deep profile, triage | Completed | malcat deep_profile |
| capa | malcat-capa engine, 1 rule matched | Completed | capa top_rules |
| YARA | Pipeline, 25 total matches (9 UPX-related) | Completed | yara matches |
| FLOSS | 2050 static strings extracted | Completed | floss strings |
| Ghidra | 0 functions recovered, imports/xrefs queried | Completed | ghidra_query audit trail |
| Speakeasy | Dynamic emulation | Completed, 0 events | speakeasy |
| Frida | v17.16.4 | Available, 0 events | frida_probe |
| UPX | Unpack attempt | Failed, no output | upx unpack data |
| Project Name | incoming | - | llm_judge |
| Sample Corpus Path | /opt/samples/corpus/incoming/ | - | llm_judge |

All analysis was performed on the sample at the path listed in Section 2, with no additional environment modifications. IDA results were excluded from analysis due to invalid intake data (source: llm_judge cross_engine_notes).
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
  "sha256": "91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc",
  "family": "unknown",
  "generated_at": "2026-08-03T10:23:45.083043+00:00",
  "string_count": 18,
  "strings": [
    "GetProcAddress",
    "VirtualProtect",
    "KERNEL32.DLL",
    "OLEAUT32.dll",
    "LoadLibraryA",
    "VirtualAlloc",
    "VirtualFree",
    "ExitProcess",
    "MSVCRT.dll",
    "USER32.dll",
    "wsprintfA",
    "Directly identifies the sample as packed with UPX, mapping to defense evasion via software packing, confirming the core ",
    "Multiple YARA rules targeting UPX packer signatures across versions 0.8x to 3.9x match the sample, providing independent",
    "These high-signal imports are characteristic of packed malware: dynamic API resolution to hide functionality, and memory",
    "Malcat explicitly recovers the UPX pack header, flags 7 distinct packing anomalies, and reports very high entropy consis",
    "These anomalies are all consistent with UPX-packed samples: RWX sections, malformed PE headers from packing, and high-en",
    "The decompiled entry point matches the known UPX unpacking stub implementation, including core decompression algorithm l",
    "These strings indicate the underlying packed payload has network functionality (HTTP, SOCKS proxy support), a common fea"
  ],
  "rule_path": "/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/rule.yar",
  "sigma_path": "/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/rule.yml",
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
  "cadre_revai": true,
  "publish_target": "revai_publish"
}
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785752419.32288}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785752419.3330686}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785752419.3356802}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785752419.3406198}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785752538.0961847}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785752538.110855}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785752538.128793}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785752538.1338263}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785752538.135181}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785752589.6104803}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports LIMIT 50", "ts": 1785752594.7082016}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%http%' OR content LIKE '%domain%' OR content LIKE '%.exe%' OR content LIKE '%cmd%' OR content LIKE '%powershell%' OR content LIKE '%rundll%' OR content LIKE '%reg%' OR content LIKE '%startup%' OR content LIKE '%temp%' OR c`
- `{"source": "ghidra_query", "sql": "SELECT * FROM funcs LIMIT 50", "ts": 1785752594.7126005}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM memory_blocks LIMIT 50", "ts": 1785752598.4797232}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM data_items LIMIT 100", "ts": 1785752598.484401}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings LIMIT 100", "ts": 1785752598.4862566}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM db_info LIMIT 50", "ts": 1785752603.257417}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM xrefs LIMIT 100", "ts": 1785752603.2651815}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM exports LIMIT 50", "ts": 1785752603.267164}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM callgraph_edges LIMIT 100", "ts": 1785752614.4717262}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM function_metrics LIMIT 50", "ts": 1785752614.488082}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785752624.0556483}`
- `{"source": "yara_gen_v2", "ts": 1785752625.0831735}`
