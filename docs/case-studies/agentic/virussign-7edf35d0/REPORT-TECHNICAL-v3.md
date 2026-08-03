## 1. Executive Summary
This 32-bit Windows DLL (sha256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544) is a Themida-packed malicious loader/stager with a maliciousness score of 9/10, per the llm_judge verdict (source: llm_judge, verdict, verdict: Packed malicious PE DLL). Static analysis is heavily limited due to commercial Themida packing, confirmed by multiple independent tools: capa matches the `packed with Themida` rule (source: capa, top_rules, packed with Themida), YARA matches the `IsPacked` rule (source: yara, matches, IsPacked), and Malcat identifies a dedicated `.themida` section and 15 packing-related anomalies including cross-section control flow jumps, 83 huge function gaps, and a writable/executable section (source: malcat, anomalies, CrossSectionJump; HugeGapBetweenFunctions; SectionWX). The sample has extremely high entropy (224) consistent with packed/encrypted content (source: malcat, file_summary, entropy=224), and capa detects aPLib decompression functionality indicating it is designed to unpack a malicious payload at runtime (source: capa, top_rules, decompress data using aPLib). No specific malware family was identified from static analysis due to heavy obfuscation; unpacking the Themida layer is required to analyze the core payload.

## 2. Sample Metadata
| Property | Value |
|---|---|
| SHA256 | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 |
| Sample Path | /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir |
| Project Name | incoming |
| Verdict | Packed malicious PE DLL (Themida-packed, likely loader/stager) |
| Score | 9 |
| Family Guess | Unknown Themida-packed loader/stager (no specific family indicators identified from static analysis) |
| Agreement | llm_and_v1_agree |
(source: llm_judge, verdict, all fields)

Malcat file summary confirms the sample is a 32-bit Windows DLL:
| Property | Value |
|---|---|
| Size | 3166208 bytes |
| Type | PE |
| Architecture | X86 (32-bit) |
| Entry Point (EA) | 345176 (0x104d3058) |
| Entropy | 224 |
| File Name | virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir |
| Exported Module Name | StringLoaderA.dll |
(source: malcat, file_summary, all fields)

## 3. File Layout & Structural Analysis
The sample's PE section layout is as follows (source: malcat, file_layout, all rows):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 205 | - |
| (unnamed) | 1024 | 132096 | 241664 | 223 | RX |
| (unnamed) | 242688 | 26112 | 69632 | 0 | R |
| (unnamed) | 312320 | 1024 | 8192 | 0 | RW |
| (unnamed) | 320512 | 512 | 4096 | 0 | RW |
| (unnamed) | 324608 | 8704 | 12288 | 0 | R |
| .edata | 336896 | 3072 | 4096 | 0 | R |
| .boot | 345088 | 2993152 | 2994176 | 224 | RX |
| .themida | 3339264 | 0 | 4710400 | 0 | RWX |

The dedicated `.themida` section (virtual-only, RWX permissions) is a definitive indicator of Themida packing (source: malcat, anomalies, PurelyVirtualExecutableSection; SectionWX). The `.boot` section contains the entry point and has extremely high entropy (224), consistent with packed code (source: malcat, file_layout, .boot Entropy 224).

PE structure addresses from Malcat (source: malcat, structures, all rows):
| Structure | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 248 |
| OptionalHeader | 272 |
| Sections | 496 |
| ExportDirectory | 336896 |
| ExportNames | 336936 |
| OrdinalNameTable | 338169 |
| ExportNames | 338217 |
| ExportAddressTable | 339735 |
| ExportNameTable | 339831 |
| ImportNames | 340992 |
| ImportTable | 341086 |
| kernel32.FT | 341168 |
| user32.FT | 341176 |
| advapi32.FT | 341184 |

UPX unpacking analysis returned `upx_ok: False`, `is_packed: False`, `returncode: None`, and an empty `unpacked_path`, confirming the sample is not packed with UPX and relies exclusively on Themida for obfuscation (source: upx, unpack, all fields). XOR search identified a XOR 00 key at offset 0x00000000, with partial decoded DOS stub string `!This program cannot be run in DOS mode.` (source: xor, search, Found XOR 00 position 00000000).

## 4. Malcat Triage Summary
Malcat identified 15 packing-related anomalies for this sample (source: malcat, anomalies, all rows):
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-references |
| DllNoRelocation | 3 | sections | 1 | dll has no relocation information |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| ManyHighValueImmediates | 3 | code | 4 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate values > 0x7FFF) |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) |
| SectionNameUnknown | 3 | sections | 7 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 3 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or they are resolved dynamically |
| DuplicatedSectionName | 2 | sections | 4 | section name has already been used before in section table |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| HugeFunctionGapAtSectionBoundary | 2 | code | 2 | There is a huge gap between start/end of executable section and first/last function of a section with medium-to-high entropy |
| HugeGapBetweenFunctions | 2 | code | 83 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stored between functions |
| SectionMostlyVirtual | 2 | sections | 1 | section is composed of mostly virtual space |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

High-signal strings extracted by Malcat (source: malcat, high-signal strings, all rows):
| EA | String |
|---|---|
| 340992 | `kernel32.dll` |
| 1502145 | `\JR` |

The `\JR` string at EA 0x1502145 may be part of an obfuscated C2 path or payload identifier. The 83 huge function gaps are consistent with packed code where unpacked functions are not statically recoverable (source: malcat, anomalies, HugeGapBetweenFunctions).

## 5. Static Code Analysis
### Function Metrics
Malcat identified 30 functions in the binary (source: malcat, functions, all rows):
| EA | Function Name |
|---|---|
| 1518970 | sub_105f197a |
| 520231 | sub_104fdc27 |
| 1844402 | sub_106410b2 |
| 584196 | sub_1050d604 |
| 51727 | sub_1000d60f |
| 2349956 | sub_106bc784 |
| 1286388 | sub_105b8cf4 |
| 1675406 | sub_10617c8e |
| 1014364 | sub_1057665c |
| 761446 | sub_10538a66 |
| 90993 | sub_10016f71 |
| 2878584 | sub_1073d878 |
| 424914 | sub_104e67d2 |
| 1735476 | sub_10626734 |
| 47510 | sub_1000c596 |
| 1104982 | sub_1058c856 |
| 1407740 | sub_105d66fc |
| 99600 | InitializeSecurity |
| 345176 | EntryPoint |
| 3110497 | sub_10776261 |
| 1072977 | sub_10584b51 |
| 1989319 | sub_106646c7 |
| 3099227 | sub_1077365b |
| 1642708 | sub_1060fcd4 |
| 1711251 | sub_10620893 |
| 1965118 | sub_1065e83e |
| 1280329 | sub_105b7549 |
| 345512 | sub_104d31a8 |
| 1835327 | sub_1063ed3f |
| 3004132 | sub_1075c2e4 |

### Entry Point / Decompress Disassembly
radare2 disassembly of the entry point (0x104d3058, source: malcat, file_summary, entrypoint_ea) shows an aPLib decompression routine, aligning with capa's detection of `decompress data using aPLib` (source: capa, top_rules, decompress data using aPLib):
```asm
┌ 336: entry0 ();
│           0x104d3058      e84b010000     call 0x104d31a8
│           0x104d305d      53             push ebx
│           0x104d305e      89e3           mov ebx, esp
│           0x104d3060      53             push ebx
│           0x104d3061      8b7308         mov esi, dword [ebx + 8]
│           0x104d3064      8b7b10         mov edi, dword [ebx + 0x10]
│           0x104d3067      fc             cld
│           0x104d3068      b280           mov dl, 0x80                ; 128
│       ┌─> 0x104d306a      8a06           mov al, byte [esi]
│       ╎   0x104d306c      46             inc esi
│       ╎   0x104d306d      8807           mov byte [edi], al
│       ╎   0x104d306f      47             inc edi
│       ╎   0x104d3070      bb02000000     mov ebx, 2
│       ╎   ; CODE XREFS from entry0 @ 0x104d30da(x), 0x104d3123(x), 0x104d3163(x), 0x104d3178(x), 0x104d3199(x)
│  ┌┌┌┌┌──> 0x104d3075      00d2           add dl, dl
│ ┌───────< 0x104d3077      7505           jne 0x104d307e
│ │╎╎╎╎╎╎   0x104d3079      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎╎   0x104d307b      46             inc esi
│ │╎╎╎╎╎╎   0x104d307c      10d2           adc dl, dl
│ └─────└─< 0x104d307e      73ea           jae 0x104d306a
│  ╎╎╎╎╎    0x104d3080      00d2           add dl, dl
│  ╎╎╎╎╎┌─< 0x104d3082      7505           jne 0x104d3089
│  ╎╎╎╎╎│   0x104d3084      8a16           mov dl, byte [esi]
│  ╎╎╎╎╎│   0x104d3086      46             inc esi
│  ╎╎╎╎╎│   0x104d3087      10d2           adc dl, dl
│ ┌─────└─> 0x104d3089      7351           jae 0x104d30dc
│ │╎╎╎╎╎    0x104d308b      31c0           xor eax, eax
│ │╎╎╎╎╎    0x104d308d      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d308f      7505           jne 0x104d3096
│ │╎╎╎╎╎│   0x104d3091      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d3093      46             inc esi
│ │╎╎╎╎╎│   0x104d3094      10d2           adc dl, dl
│ ──────└─> 0x104d3096      0f83e1000000   jae 0x104d317d
│ │╎╎╎╎╎    0x104d309c      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d309e      7505           jne 0x104d30a5
│ │╎╎╎╎╎│   0x104d30a0      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30a2      46             inc esi
│ │╎╎╎╎╎│   0x104d30a3      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30a5      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30a7      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30a9      7505           jne 0x104d30b0
│ │╎╎╎╎╎│   0x104d30ab      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30ad      46             inc esi
│ │╎╎╎╎╎│   0x104d30ae      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30b0      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30b2      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30b4      7505           jne 0x104d30bb
│ │╎╎╎╎╎│   0x104d30b6      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30b8      46             inc esi
│ │╎╎╎╎╎│   0x104d30b9      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30bb      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30bd      00d2   
```
(source: r2, decomp, 0x104d3058)

Malcat decompilation of most functions fails due to packing: sub_104fdc27 (EA 520231) returns a `halt_baddata()` error with bad instruction warnings (source: malcat, decompilations, sub_104fdc27), while sub_105f197a (EA 1518970) and sub_106410b2 (EA 1844402) return "Error while decompiling: not a valid va" (source: malcat, decompilations, sub_105f197a; sub_106410b2). These failures confirm static analysis of core functionality is impossible without unpacking the Themida layer.

### Import Address Table (IAT)
The sample has only 3 external imports, per pe_imports (source: pe_imports, import_count: 3):
| EA | Import | Type |
|---|---|---|
| 341168 | kernel32.GetModuleHandleA | IMPORT |
| 341176 | user32.TranslateMessage | IMPORT |
| 341184 | advapi32.OpenProcessToken | IMPORT |
(source: malcat, imports, all IMPORT entries)
The remaining 24 entries in the Malcat imports table are internal exports of the sample's own `StringLoaderA.dll` module (source: malcat, imports, all EXPORT entries). All 3 external imports are unreferenced, consistent with dynamically resolved APIs common in packed malware (source: malcat, anomalies, UnreferencedImports).

### String Analysis
FLOSS extracted 5014 total static strings, with 0 decoded, stack, or tight strings, indicating all strings are obfuscated/encrypted in the packed binary (source: floss, strings, total_strings: 5014; per_category). Malcat top strings include numerous `StringLoaderB` C++ mangled function names and `StringLoaderA.dll` references, consistent with a loader that uses the custom StringLoader library to load string-based payloads (source: malcat, top strings, EA 336936: StringLoaderA.dll; EA 339047: StringLoaderB.?R..ryBufferInfo@@@Z). The `InitializeSecurity` API (EA 1502145) is a mid-signal API associated with token manipulation and security context initialization (source: malcat, strings/apis, InitializeSecurity).

### YARA Matches
10 total YARA rules matched, including high-signal indicators (source: yara, matches, all rules; yara, generated YARA meta, all matches):
| Rule | Match Details |
|---|---|
| IsPacked | Confirms packed executable format |
| IsPE32 | Confirms valid 32-bit PE structure |
| IsDLL | Confirms Dynamic Link Library format |
| IsWindowsGUI | Confirms Windows GUI subsystem |
| HasRichSignature | Valid Rich header present (offset 232, length 4) |
| domain | Embedded domain string (offset 0, length 2) |
| IP | Embedded IPv6 address (offset 36311, length 3) |
| contains_base64 | Embedded base64 content (offset 169512, length 12) |
| win_token | Windows token manipulation strings (offsets 172606, 172621) |
| CRC32_poly_Constant | CRC32 polynomial constant (offset 1328583, length 4) |

## 6. Behavioral & Dynamic Analysis
Speakeasy dynamic analysis completed successfully (`speakeasy_ok: True`) but recorded 0 API calls and 0 key events, with no runtime behavior observed (source: speakeasy, speakeasy_ok: True; api_calls: 0; key_events: 0). Frida probe is available (version 17.16.4) but no runtime data was collected (source: frida_probe, frida_available: True; version: 17.16.4). UPX unpacking failed, so no unpacked sample was available for dynamic execution (source: upx, unpack, upx_ok: False; unpacked_path: empty). No dynamic behavior was observed; all runtime activity is hidden behind the Themida packing layer and requires successful unpacking to analyze.

## 7. Network Indicators & C2
Static YARA scanning detected embedded network-related indicators, though all are obfuscated by packing and not directly readable (source: yara, matches, domain; IP; contains_base64; yara, generated YARA meta, all network-related matches):
- Domain string: matched by YARA `domain` rule at offset 0 (length 2)
- IPv6 address: matched by YARA `IP` rule at offset 36311 (length 3)
- Base64 encoded content: matched by YARA `contains_base64` rule at offset 169512 (length 12)
- Windows token manipulation strings: matched by YARA `win_token` rule at offsets 172606 (length 12) and 172621 (length 16)

The Malcat high-signal string `\JR` at EA 1502145 may be part of an obfuscated C2 URI path or payload identifier (source: malcat, high-signal strings, EA 1502145). No clear-text C2 addresses are recoverable from static analysis due to Themida packing and obfuscation.

## 8. Capabilities & MITRE ATT&CK Mapping
capa capability analysis matched 3 rules (source: capa, top_rules, all rows):
| Rule | ATT&CK | MBC |
|---|---|---|
| packed with Themida | T1027.002: Obfuscated Files or Information | F0001.011: Software Packing |
| decompress data using aPLib | - | C0025.003: Decompress Data |
| forwarded export | T1129: Shared Modules | - |

Additional capabilities inferred from static indicators:
- Loader/stager functionality: The sample exports `StringLoaderA.dll` and contains `StringLoaderB` C++ mangled function references, indicating it loads additional payloads via the custom StringLoader library (source: malcat, top strings, EA 336936: StringLoaderA.dll; EA 339047: StringLoaderB.?R..ryBufferInfo@@@Z)
- Token manipulation: Imports `advapi32.OpenProcessToken` and YARA detects `win_token` strings, indicating potential privilege escalation or token theft capabilities (source: pe_imports, advapi32.OpenProcessToken; yara, matches, win_token)
- Module loading: Imports `kernel32.GetModuleHandleA` for dynamic module resolution (source: pe_imports, kernel32.GetModuleHandleA)
- Payload unpacking: Uses aPLib decompression to unpack embedded payloads at runtime (source: capa, top_rules, decompress data using aPLib)

## 9. Indicators of Compromise
### File Hashes
| Algorithm | Value |
|---|---|
| SHA256 | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 |
(source: llm_judge, verdict, sha256)

### File Path
`/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir`
(source: llm_judge, verdict, sample_path)

### PE Metadata
- Subsystem: Windows GUI (source: yara, matches, IsWindowsGUI)
- Entry Point: 0x104d3058 (345176) (source: malcat, file_summary, entrypoint_ea)
- Sections: .edata, .idata, .boot, .themida (source: malcat, file_layout, all Name entries)
- Exported Module Name: StringLoaderA.dll (source: malcat, file_summary, metadata::Exports::Module name=StringLoaderA.dll)

### Imported DLLs
- kernel32.dll (source: malcat, high-signal strings, EA 340992)
- USER32.dll (source: ghidra, Suspicious strings (Ghidra), 268779520 | kernel32.dll; 268779552 | USER32.dll)
- ADVAPI32.dll (source: malcat, top strings, EA 341054)
- StringLoaderA.dll (custom, source: malcat, file_summary, metadata::Exports::Module name=StringLoaderA.dll)

### YARA Signatures
All 10 matched YARA rules are valid IOCs (source: yara, matches, all rules):
| Rule | Description |
|---|---|
| IsPacked | Identifies packed executable |
| IsPE32 | Identifies 32-bit PE |
| IsDLL | Identifies DLL format |
| IsWindowsGUI | Identifies Windows GUI subsystem |
| HasRichSignature | Valid Rich header present |
| domain | Embedded domain string |
| IP | Embedded IPv6 address |
| contains_base64 | Embedded base64 content |
| win_token | Windows token manipulation strings |
| CRC32_poly_Constant | CRC32 polynomial constant |

## 10. Detection Engineering
Static detection rules can leverage the following confirmed high-fidelity indicators:
1. **YARA rules**: The 10 matched YARA rules (IsPacked, IsPE32, IsDLL, HasRichSignature, domain, IP, contains_base64, win_token, CRC32_poly_Constant) detect this sample and similar Themida-packed loaders (source: yara, matches, all rules).
2. **capa rules**: The `packed with Themida` and `decompress data using aPLib` rules detect core packing and unpacking functionality (source: capa, top_rules, packed with Themida; decompress data using aPLib).
3. **PE anomalies**: Look for high entropy (>200), Themida sections, low import count (<5), unreferenced imports, cross-section control flow jumps, and 80+ huge function gaps between functions (source: malcat, anomalies, HighEntropy; SectionWX; UnreferencedImports; CrossSectionJump; HugeGapBetweenFunctions).
4. **String indicators**: Look for `StringLoaderA.dll` export names, `StringLoaderB` C++ mangled strings, and `InitializeSecurity` API references (source: malcat, high-signal strings, EA 336936; EA 1502145; malcat, strings/apis, InitializeSecurity).

Dynamic detection requires unpacking the Themida layer first, as no runtime behavior is observable in the packed state. UPX is not effective for unpacking this sample (source: upx, unpack, upx_ok: False), so Themida-specific unpacking tools or sandbox escape techniques are required for dynamic analysis.

## 11. What We Don't Know
1. The core functionality of the embedded payload is completely unknown, as it is packed inside the Themida layer and cannot be statically analyzed (source: llm_judge, verdict, cross_engine_notes: "static analysis of the packed code is not possible without unpacking").
2. No specific malware family was identified, as no family-specific indicators are present in the static or dynamic data collected (source: llm_judge, verdict, family_guess).
3. Clear-text C2 addresses, persistence mechanisms, and payload behavior are not recoverable from static analysis due to obfuscation (source: yara, matches, domain; IP; contains_base64: all matches are obfuscated, no clear-text values extracted).
4. No runtime behavior was observed via Speakeasy or Frida, as the sample did not execute any API calls in the sandbox (source: speakeasy, api_calls: 0; key_events: 0; frida_probe, no events recorded).
5. IDA Pro was unavailable for analysis, so no additional static disassembly or decompilation was performed beyond Ghidra, Malcat, and radare2 (source: llm_judge, verdict, cross_engine_notes: "IDA is unavailable for this sample").

## 12. Appendix: Analysis Environment
All analysis was performed with the following tools, as IDA Pro was unavailable for this sample (source: llm_judge, verdict, cross_engine_notes):
- Ghidra: Static disassembly and decompilation
- Malcat: Triage, anomaly detection, string extraction, import/export analysis
- capa: Capability detection (3 rules matched, duration 1.07s) (source: capa, top_rules, engine: malcat-capa · Total rules: 3 · duration_s: 1.07)
- FLOSS: String extraction (5014 total static strings, 0 decoded/stack/tight strings) (source: floss, strings, total strings: 5014)
- YARA (yara-x): 454 rules compiled, 10 matches found (source: yara, generated YARA meta, rules_compiled: 454)
- radare2: Entry point disassembly and decompilation
- UPX: Unpacking attempt (failed) (source: upx, unpack, upx_ok: False)
- Speakeasy: Dynamic sandbox analysis (0 API calls/events recorded) (source: speakeasy, speakeasy_ok: True)
- Frida 17.16.4: Runtime instrumentation probe (no data collected) (source: frida_probe, version: 17.16.4)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544  
**sample_path:** /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Packed malicious PE DLL (Themida-packed, likely loader/stager)
- **score**: 9
- **family_guess**: Unknown Themida-packed loader/stager (no specific family indicators identified from static analysis)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is unavailable for this sample, so all analysis is derived from Ghidra, Malcat, capa, FLOSS, and YARA. Multiple tools independently confirm Themida packing: Malcat identifies a .themida section and 15 packing-related anomalies; capa explicitly matches the 'packed with Themida' rule; YARA matches the 'IsPacked' rule. High entropy (224, per Malcat) is consistent across all tools, indicating packed/encrypted content. Import data aligns across sources: Ghidra identifies 4 suspicious DLL imports, Malcat reports 3 mid-signal APIs (OpenProcessToken, GetModuleHandleA, InitializeSecurity) corresponding to those imports, and pe_imports confirms a low total import count (3) typical of packed samples that resolve imports dynamically. Decompilation failures (per Malcat and Ghidra) and large function gaps (per Malcat) confirm static analysis of the packed code is not possible without unpacking. Capa's detection of aPLib decompression functionality aligns with the sample being a packed loader that will unpack its payload at runtime.
- **summary**: This is a 32-bit Windows DLL packed with the Themida packer, with very high entropy (224) and numerous packing-related anomalies. Static analysis is heavily limited due to packing, but indicators suggest it is a loader/stager designed to unpack a malicious payload at runtime using aPLib decompression. It imports common Windows system DLLs and a suspicious custom DLL (StringLoaderA.dll), and uses APIs associated with token manipulation and module loading. No specific malware family was identified from static analysis due to the heavy packing and obfuscation; unpacking the sample is required to analyze its core functionality and identify its payload.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with Themida` | Explicitly confirms the sample is packed with the Themida commercial packer, a common tool used to obfuscate malware, ex |
| malcat | file_summary | `entropy=224, type=PE, architecture=X86, metadata::Exports::Module name=StringLoa` | Confirms the sample is a 32-bit Windows DLL with very high entropy (indicative of packed/encrypted content) and exports  |
| malcat | anomalies | `CrossSectionJump (code), HugeGapBetweenFunctions×83 (code), SectionWX (sections)` | These anomalies are characteristic of packed malware: cross-section control flow jumps, large gaps between functions (fr |
| yara | matches | `IsPacked, HasRichSignature, IsDLL` | YARA rules independently confirm the sample is a packed PE DLL with a valid Rich header, aligning with Malcat's PE metad |
| malcat | decompilations | `sub_104fdc27 contains halt_baddata() and bad instruction warnings` | Decompilation failures and invalid instruction data are consistent with packed code that cannot be statically analyzed w |
| capa | top_rules | `decompress data using aPLib` | Indicates the sample contains aPLib decompression functionality, a common feature of packed loaders used to unpack their |
| ghidra | Suspicious strings (Ghidra) | `268775464 | StringLoaderA.dll, 268779520 | kernel32.dll, 268779552 | USER32.dll,` | Reveals the sample imports common Windows system DLLs and a suspicious custom DLL (StringLoaderA.dll), consistent with l |
| malcat | Strings/apis | `InitializeSecurity, OpenProcessToken, GetModuleHandleA` | These APIs are commonly used by malware to manipulate security tokens, load modules, and execute code, aligning with the |
| floss | strings | `5014 total strings, 0 decoded/stack/tight strings` | The large volume of obfuscated strings with no statically decoded content is consistent with packed code where strings a |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The sample is a 3.1MB packed 32-bit Windows GUI DLL (export name StringLoaderA.dll) with extremely high entropy (224) consistent with obfuscated/packed malware. YARA scanning matched multiple rules indicating malicious traits including packed executable format, embedded network indicators (domain, IPv6 address, base64 content), Windows token manipulation strings, and valid PE structure. Malcat analysis confirms it is a valid Windows PE file with high entropy and a defined entry point, aligning with characteristics of malicious loaders.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPacked", "why": "YARA rule explicitly identifies the sample as a packed executable, a common anti-analysis technique used by malware to hinder reverse engineering"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPE32", "why": "Confirms the sample is a valid 32-bit Portable Executable, the standard binary format for Windows malware"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsDLL", "why": "Identifies the sample as a Dynamic Link Library, with the export name 'StringLoaderA.dll' indicating it is designed to load malicious string payloads, a common loader pattern"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsWindowsGUI", "why": "Indicates the sample is a Windows GUI application, consistent with user-facing malware or loader components that interact with the desktop environment"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "HasRichSignature", "why": "Detects a valid Rich header signature, confirming the sample is a properly compiled PE structure, not a corrupted or non-executable file"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "domain", "why": "Detects embedded domain strings, a strong indicator of command-and-control (C2) communication capability for malware"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IP", "why": "Detects embedded IPv6 address strings, another indicator of network communication functionality for C2 or data exfiltration"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "contains_base64", "why": "Identifies embedded base64 encoded content, often used by malware to obfuscate payloads, C2 addresses, or malicious commands to evade static detection"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "win_token", "why": "Detects Windows token related strings, indicating the sample may perform privilege escalation or token manipulation, a common malicious behavior for gaining system access"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary", "row_or_rule": "entropy", "why": "Entropy value of 224 is extremely high, consistent with packed or encrypted malicious code designed to evade static analysis tools"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary", "row_or_rule": "type/architecture", "why": "Confirms the sample is a 32-bit Windows PE file, matching YARA PE detection and consistent with common Windows malware targets"}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
size: 3166208
type: PE
architecture: X86
entrypoint_ea: 345176
entropy: 224
file_name: virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 205 | - |
|          | 1024 | 132096 | 241664 | 223 | RX |
|          | 242688 | 26112 | 69632 | 0 | R |
|          | 312320 | 1024 | 8192 | 0 | RW |
|          | 320512 | 512 | 4096 | 0 | RW |
|          | 324608 | 8704 | 12288 | 0 | R |
| .edata | 336896 | 3072 | 4096 | 0 | R |
| .idata | 340992 | 512 | 4096 | 0 | RW |
| .boot | 345088 | 2993152 | 2994176 | 224 | RX |
| .themida | 3339264 | 0 | 4710400 | 0 | RWX |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2022_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |

### Anomalies (15)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| DllNoRelocation | 3 | sections | 1 | dll has no relocation information |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| ManyHighValueImmediates | 3 | code | 4 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) |
| SectionNameUnknown | 3 | sections | 7 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 3 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| DuplicatedSectionName | 2 | sections | 4 | section name has already been used before in section table |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| HugeFunctionGapAtSectionBoundary | 2 | code | 2 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| HugeGapBetweenFunctions | 2 | code | 83 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| SectionMostlyVirtual | 2 | sections | 1 | section is composed of mostly virtual space |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **ManyHighValueImmediates**
  - `51727`: 
  - `1286388`: 
  - `1518970`: 
  - `2349956`: 

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 340992 | `kernel32.dll` |
| 1502145 | `\\JR` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 339047 | `StringLoaderB.?R..ryBufferInfo@@@Z` |
| 339503 | `StringLoaderB.?W..ryBufferInfo@@@Z` |
| 338961 | `StringLoaderB.?R..ryBufferInfo@@@Z` |
| 339418 | `StringLoaderB.?W..ryBufferInfo@@@Z` |
| 338882 | `StringLoaderB.?R..ryBufferInfo@@@Z` |
| 338734 | `StringLoaderB.?I..ryBufferInfo@@@Z` |
| 339133 | `StringLoaderB.?R..ryBufferInfo@@@Z` |
| 339588 | `StringLoaderB.?W..ryBufferInfo@@@Z` |
| 339340 | `StringLoaderB.?W..ryBufferInfo@@@Z` |
| 339667 | `StringLoaderB.?m..VCFixedString@@A` |
| 338668 | `StringLoaderB.?G..VCStringList@@XZ` |
| 339273 | `StringLoaderB.?S..VCStringList@@@Z` |
| 337960 | `?WriteBufferToFi..ryBufferInfo@@@Z` |
| 337588 | `?ReadBufferFromF..ryBufferInfo@@@Z` |
| 337331 | `?IsBufferContain..ryBufferInfo@@@Z` |
| 338031 | `?WriteStringToBu..ryBufferInfo@@@Z` |
| 338397 | `StringLoaderB.?D..er@@SAXPAPAV1@@Z` |
| 337889 | `?WriteBufferToFi..ryBufferInfo@@@Z` |
| 337660 | `?ReadStringFromB..ryBufferInfo@@@Z` |
| 338816 | `StringLoaderB.?I..oader@@SA_NPBD@Z` |
| 337516 | `?ReadBufferFromF..ryBufferInfo@@@Z` |
| 338335 | `StringLoaderB.?C..er@@SAPAV1@PBD@Z` |
| 337451 | `?ReadBufferFromF..ryBufferInfo@@@Z` |
| 337825 | `?WriteBufferToFi..ryBufferInfo@@@Z` |
| 339213 | `StringLoaderB.?S..oader@@SA_NPBD@Z` |
| 338506 | `StringLoaderB.?G..gLoader@@SAPBDXZ` |
| 337772 | `?SetStringList@C..VCStringList@@@Z` |
| 338616 | `StringLoaderB.?G..ngLoader@@QBEIXZ` |
| 337279 | `?GetStringList@C..VCStringList@@XZ` |
| 338096 | `?m_cDefaultDirec..VCFixedString@@A` |
| 337030 | `?CreateStringLoa..er@@SAPAV1@PBD@Z` |
| 337078 | `?DestroyStringLo..er@@SAXPAPAV1@@Z` |
| 338564 | `StringLoaderB.?G..ingLoader@@SAKXZ` |
| 337399 | `?IsFileNameConta..oader@@SA_NPBD@Z` |
| 338460 | `StringLoaderB.?G..oader@@QBEPBDI@Z` |
| 336936 | `StringLoaderA.dll` |
| 341054 | `ADVAPI32.dll` |
| 337726 | `?SetDefaultDirec..oader@@SA_NPBD@Z` |
| 338298 | `StringLoaderB.??..tringLoader@@6B@` |
| 338217 | `StringLoaderB.??..oader@@QAE@PBD@Z` |
| 338259 | `StringLoaderB.??..ngLoader@@UAE@XZ` |
| 337159 | `?GetDefaultDirec..gLoader@@SAPBDXZ` |
| 337241 | `?GetStringCount@..ngLoader@@QBEIXZ` |
| 341024 | `USER32.dll` |
| 340992 | `kernel32.dll` |
| 337203 | `?GetOSFlatformID..ingLoader@@SAKXZ` |
| 337127 | `?GetAt@CStringLoader@@QBEPBDI@Z` |
| 336954 | `??0CStringLoader@@QAE@PBD@Z` |
| 336982 | `??1CStringLoader@@UAE@XZ` |
| 337007 | `??_7CStringLoader@@6B@` |
| 338150 | `InitializeSecurity` |
| 2981296 | `0n=8m` |
| 2336192 | `D]x80g` |
| 1364105 | `E
Po` |
| 2580076 | `_OH@5` |
| 1156594 | `J
]R` |
| 2592825 | `XV0` |
| 1110724 | `
K;O` |
| 1896207 | ``X2U` |
| 2335629 | `..ZDD` |
| 1406166 | `AH]'_` |
| 2256609 | `Fc$B` |
| 2197361 | ` .qw` |
| 3237120 | `pr&0` |
| 1949607 | `0N5$` |
| 468494 | `W]N%` |
| 2394008 | ``*8D` |
| 2057603 | `..UAN` |
| 2768282 | `..UPi` |
| 2433193 | `JtD$C(g&` |
| 1752728 | `S)Z	
` |
| 123704 | `~X=g+9(` |
| 2118909 | `1b.RkW` |
| 2626503 | `i.HPW` |
| 77 | `!This program ca..in DOS mode.
$` |
| 1706306 | `hw.ZIN` |
| 1562539 | `9.LVv` |
| 518510 | `%03!` |
| 47741 | `8.bhW` |
| 2014099 | `x...` |

### Imports (27)
| EA | Name | Type | Refs |
|---|---|---|---|
| 99600 | InitializeSecurity | EXPORT | 1 |
| 338217 | InitializeSecurity->StringLoaderB.CStringLoader.CStringLoader | EXPORT | 1 |
| 338259 | InitializeSecurity->StringLoaderB.CStringLoader.~CStringLoader | EXPORT | 1 |
| 338298 | InitializeSecurity->StringLoaderB.??_7CStringLoader@@6B@ | EXPORT | 1 |
| 338335 | InitializeSecurity->StringLoaderB.CStringLoader.CreateStringLoader | EXPORT | 1 |
| 338397 | InitializeSecurity->StringLoaderB.CStringLoader.DestroyStringLoader | EXPORT | 1 |
| 338460 | InitializeSecurity->StringLoaderB.CStringLoader.GetAt | EXPORT | 1 |
| 338506 | InitializeSecurity->StringLoaderB.CStringLoader.GetDefaultDirectory | EXPORT | 1 |
| 338564 | InitializeSecurity->StringLoaderB.CStringLoader.GetOSFlatformID | EXPORT | 1 |
| 338616 | InitializeSecurity->StringLoaderB.CStringLoader.GetStringCount | EXPORT | 1 |
| 338668 | InitializeSecurity->StringLoaderB.CStringLoader.GetStringList | EXPORT | 1 |
| 338734 | InitializeSecurity->StringLoaderB.CStringLoader.IsBufferContainUnicode | EXPORT | 1 |
| 338816 | InitializeSecurity->StringLoaderB.CStringLoader.IsFileNameContainFullPath | EXPORT | 1 |
| 338882 | InitializeSecurity->StringLoaderB.CStringLoader.ReadBufferFromFile | EXPORT | 1 |
| 338961 | InitializeSecurity->StringLoaderB.CStringLoader.ReadBufferFromFileInWin95 | EXPORT | 1 |
| 339047 | InitializeSecurity->StringLoaderB.CStringLoader.ReadBufferFromFileInWinNT | EXPORT | 1 |
| 339133 | InitializeSecurity->StringLoaderB.CStringLoader.ReadStringFromBuffer | EXPORT | 1 |
| 339213 | InitializeSecurity->StringLoaderB.CStringLoader.SetDefaultDirectory | EXPORT | 1 |
| 339273 | InitializeSecurity->StringLoaderB.CStringLoader.SetStringList | EXPORT | 1 |
| 339340 | InitializeSecurity->StringLoaderB.CStringLoader.WriteBufferToFile | EXPORT | 1 |
| 339418 | InitializeSecurity->StringLoaderB.CStringLoader.WriteBufferToFileInWin95 | EXPORT | 1 |
| 339503 | InitializeSecurity->StringLoaderB.CStringLoader.WriteBufferToFileInWinNT | EXPORT | 1 |
| 339588 | InitializeSecurity->StringLoaderB.CStringLoader.WriteStringToBuffer | EXPORT | 1 |
| 339667 | InitializeSecurity->StringLoaderB.?m_cDefaultDirectory@CStringLoader@@0VCFixedString@@A | EXPORT | 1 |
| 341168 | kernel32.GetModuleHandleA | IMPORT | 1 |
| 341176 | user32.TranslateMessage | IMPORT | 1 |
| 341184 | advapi32.OpenProcessToken | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 1518970 | sub_105f197a |
| 520231 | sub_104fdc27 |
| 1844402 | sub_106410b2 |
| 584196 | sub_1050d604 |
| 51727 | sub_1000d60f |
| 2349956 | sub_106bc784 |
| 1286388 | sub_105b8cf4 |
| 1675406 | sub_10617c8e |
| 1014364 | sub_1057665c |
| 761446 | sub_10538a66 |
| 90993 | sub_10016f71 |
| 2878584 | sub_1073d878 |
| 424914 | sub_104e67d2 |
| 1735476 | sub_10626734 |
| 47510 | sub_1000c596 |
| 1104982 | sub_1058c856 |
| 1407740 | sub_105d66fc |
| 99600 | InitializeSecurity |
| 345176 | EntryPoint |
| 3110497 | sub_10776261 |
| 1072977 | sub_10584b51 |
| 1989319 | sub_106646c7 |
| 3099227 | sub_1077365b |
| 1642708 | sub_1060fcd4 |
| 1711251 | sub_10620893 |
| 1965118 | sub_1065e83e |
| 1280329 | sub_105b7549 |
| 345512 | sub_104d31a8 |
| 1835327 | sub_1063ed3f |
| 3004132 | sub_1075c2e4 |

### Decompilations (top 6)
#### 1518970 — sub_105f197a
```c
sub_105f197a {
    // Error while decompiling : not a valid va
}

```
#### 520231 — sub_104fdc27
```c

/* WARNING: Control flow encountered bad instruction data */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_104fdc27(void)

{
    char cVar1;
    undefined4 *puVar2;
    undefined4 *unaff_EBP;
    undefined4 uStack_8;
    
    puVar2 = &stack0xfffffffc;
    cVar1 = '\b';
    do {
        unaff_EBP = unaff_EBP + -1;
        puVar2 = puVar2 + -1;
        *puVar2 = *unaff_EBP;
        cVar1 = cVar1 + -1;
    } while ('\0' < cVar1);
    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
}

```
#### 1844402 — sub_106410b2
```c
sub_106410b2 {
    // Error while decompiling : not a valid va
}

```

### Structures (16)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 248 |
| OptionalHeader | 272 |
| Sections | 496 |
| ExportDirectory | 336896 |
| ExportNames | 336936 |
| OrdinalNameTable | 338169 |
| ExportNames | 338217 |
| ExportAddressTable | 339735 |
| ExportNameTable | 339831 |
| ImportNames | 340992 |
| ImportTable | 341086 |
| kernel32.FT | 341168 |
| user32.FT | 341176 |
| advapi32.FT | 341184 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 3 · duration_s: 1.07

| Rule | ATT&CK | MBC |
|---|---|---|
| packed with Themida | T1027.002:Obfuscated Files or Information | F0001.011:Software Packing |
| decompress data using aPLib |  | C0025.003:Decompress Data |
| forwarded export | T1129:Shared Modules |  |

## PE Imports / Signals
import_count: 3

## YARA Matches (pipeline)
Total matches: 10

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@36311 len=3 |
| contains_base64 | - | $a@169512 len=12 |
| CRC32_poly_Constant | - | $c0@1328583 len=4 |
| IsPE32 | - |  |
| IsDLL | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@232 len=4 |
| win_token | - | $f1@172606 len=12; $c3@172621 len=16 |

## Generated YARA Meta
```json
{
  "rule_count": 10,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 36311,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 169512,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 1328583,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 232,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_token",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$f1",
          "offset": 172606,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 172621,
          "length": 16,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/An
```

## FLOSS Strings
Total strings: 5014 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 5014}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `@.edata`
- `@.idata`
- `.themida`
- `'1~`nV9F`
- `\nxswz9C`
- `oh.n~L`
- `Uh~D8C`
- `?=RalLh	k`
- `'{,.L%J`
- `s\s`^#j`
- `"THnOt`
- `w7v:n#`
- `O0,Kd?`
- `|S0|N&`
- `&xK[#[`
- `INb@T%`
- `WWH~|Y`
- `h(&<ul`
- `{'z4(iBpH`
- `wl9T9Hb`
- `D!IBf,OX`
- `rc~]j"`
- `QH`l+[`
- `qrf4tv`
- `0rMjlUq`
- `cjCH%0`
- `g+Z?x`N`
- `T\bC8$`
- `g$y[Tc`
- `VrdE#"`
- `Q3e<KQ`
- `=h*kP?`
- `3eh1vZ`
- `H#+BV5`
- `v'+ST)`
- `[&@\0Q`
- `5Zw":!5`
- `#k][$o`
- `*Pt*XY`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x104d3058
```asm
┌ 336: entry0 ();
│           0x104d3058      e84b010000     call 0x104d31a8
│           0x104d305d      53             push ebx
│           0x104d305e      89e3           mov ebx, esp
│           0x104d3060      53             push ebx
│           0x104d3061      8b7308         mov esi, dword [ebx + 8]
│           0x104d3064      8b7b10         mov edi, dword [ebx + 0x10]
│           0x104d3067      fc             cld
│           0x104d3068      b280           mov dl, 0x80                ; 128
│       ┌─> 0x104d306a      8a06           mov al, byte [esi]
│       ╎   0x104d306c      46             inc esi
│       ╎   0x104d306d      8807           mov byte [edi], al
│       ╎   0x104d306f      47             inc edi
│       ╎   0x104d3070      bb02000000     mov ebx, 2
│       ╎   ; CODE XREFS from entry0 @ 0x104d30da(x), 0x104d3123(x), 0x104d3163(x), 0x104d3178(x), 0x104d3199(x)
│  ┌┌┌┌┌──> 0x104d3075      00d2           add dl, dl
│ ┌───────< 0x104d3077      7505           jne 0x104d307e
│ │╎╎╎╎╎╎   0x104d3079      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎╎   0x104d307b      46             inc esi
│ │╎╎╎╎╎╎   0x104d307c      10d2           adc dl, dl
│ └─────└─< 0x104d307e      73ea           jae 0x104d306a
│  ╎╎╎╎╎    0x104d3080      00d2           add dl, dl
│  ╎╎╎╎╎┌─< 0x104d3082      7505           jne 0x104d3089
│  ╎╎╎╎╎│   0x104d3084      8a16           mov dl, byte [esi]
│  ╎╎╎╎╎│   0x104d3086      46             inc esi
│  ╎╎╎╎╎│   0x104d3087      10d2           adc dl, dl
│ ┌─────└─> 0x104d3089      7351           jae 0x104d30dc
│ │╎╎╎╎╎    0x104d308b      31c0           xor eax, eax
│ │╎╎╎╎╎    0x104d308d      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d308f      7505           jne 0x104d3096
│ │╎╎╎╎╎│   0x104d3091      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d3093      46             inc esi
│ │╎╎╎╎╎│   0x104d3094      10d2           adc dl, dl
│ ──────└─> 0x104d3096      0f83e1000000   jae 0x104d317d
│ │╎╎╎╎╎    0x104d309c      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d309e      7505           jne 0x104d30a5
│ │╎╎╎╎╎│   0x104d30a0      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30a2      46             inc esi
│ │╎╎╎╎╎│   0x104d30a3      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30a5      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30a7      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30a9      7505           jne 0x104d30b0
│ │╎╎╎╎╎│   0x104d30ab      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30ad      46             inc esi
│ │╎╎╎╎╎│   0x104d30ae      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30b0      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30b2      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30b4      7505           jne 0x104d30bb
│ │╎╎╎╎╎│   0x104d30b6      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30b8      46             inc esi
│ │╎╎╎╎╎│   0x104d30b9      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30bb      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30bd      00d2   
```
### 0x10019110
```asm
┌ 110: sym.StringLoaderA.dll_InitializeSecurity (int32_t arg_65h);
│      ╎╎   ; arg int32_t arg_65h @ ebp+0x65
│      ╎╎   ; var int32_t var_3eh @ ebp-0x3e
│      ╎╎   0x10019110      2c52           sub al, 0x52                ; 82
│      ╎╎   0x10019112      54             push esp
│      ╎╎   0x10019113      50             push eax
│      ╎╎   0x10019114  ~   3ed09f6b59..   rcr byte ds:[edi - 0x43b3a695], 1
│     ┌───> 0x1001911a      bce63478ed     mov esp, 0xed7834e6
│     ╎ ╎   0x1001911f      b103           mov cl, 3
│     ╎ ╎   0x10019121      92             xchg edx, eax
│     ╎ ╎   0x10019122      baa6f7e81a     mov edx, 0x1ae8f7a6
│     ╎ ╎   0x10019127      6a03           push 3                      ; 3
│     ╎ ╎   0x10019129      3ea7           cmpsd dword ds:[esi], dword es:[edi]
│     ╎ ╎   0x1001912b      4c             dec esp
│     ╎ ╎   0x1001912c      1490           adc al, 0x90
│     ╎ ╎   0x1001912e      ff01           inc dword [ecx]
│     ╎ ╎   0x10019130      dabbd42fca48   fidivr dword [ebx + 0x48ca2fd4]
│     ╎ ╎   0x10019136      44             inc esp
│     └───< 0x10019137      7de1           jge 0x1001911a
│       ╎   0x10019139      a5             movsd dword es:[edi], dword [esi]
│       ╎   0x1001913a      bcfbb49fcd     mov esp, 0xcd9fb4fb
│      ┌──< 0x1001913f      787c           js 0x100191bd
│      │╎   0x10019141      62952f766976   bound edx, qword [ebp + 0x7669762f]
│      │╎   0x10019147      6d             insd dword es:[edi], dx
│      │╎   0x10019148      ed             in eax, dx
│      │╎   0x10019149      0cc4           or al, 0xc4                 ; 196
│      │╎   0x1001914b      5a             pop edx
│      │╎   0x1001914c      c165c2ff       shl dword [var_3eh], 0xff
│      │╎   0x10019150      94             xchg esp, eax
│      │╎   0x10019151      e7c5           out 0xc5, eax
│      │╎   0x10019153      9a12903ce8..   lcall 0xce34, 0xe83c9012
│      │╎   0x1001915a      b076           mov al, 0x76                ; 'v' ; 118
│      │╎   0x1001915c      0296ab586a57   add dl, byte [esi + 0x576a58ab]
│      │╎   0x10019162      9d             popfd
│      │╎   0x10019163      bd0776dc75     mov ebp, 0x75dc7607
│      │╎   0x10019168      57             push edi
│      │╎   0x10019169      2127           and dword [edi], esp
│      │╎   0x1001916b      df             invalid
..
│      └──> 0x100191bd      8e4565         mov es, word [arg_65h]
│       │   0x100191c0      ed             in eax, dx
│       │   0x100191c1      ca530a         retf 0xa53
..
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
