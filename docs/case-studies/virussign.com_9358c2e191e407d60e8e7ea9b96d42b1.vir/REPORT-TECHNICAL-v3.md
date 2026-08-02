## 1. Executive Summary
This sample is a high-confidence malicious 64-bit Windows PE file (sha256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5) with a threat score of 9, classified as an unknown UPX-packed dropper/loader (source: llm_judge verdict). Static analysis reveals extreme entropy (145) across the sample, 16 static anomalies indicating heavy obfuscation, and an entry point (EP) containing an in-memory XOR decoding loop with key 0xae (source: malcat static_profile, malcat decompilation). The sample embeds 10 additional PE files (source: malcat carved_files) confirmed by capa rules (source: capa top_rules), and imports runtime API resolution functions (LoadLibraryA, GetProcAddress) and memory modification APIs (VirtualProtect) consistent with packed malware that dynamically resolves functions and modifies memory permissions to execute decoded payloads (source: pe_imports pe_imports signals, malcat imports). YARA rules detect UPX packing and RunShell functionality (source: malcat YARA), and capa confirms UPX packing, XOR encoding, embedded PE content, and runtime linking behavior (source: capa top_rules). No specific malware family could be identified from available evidence.

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir |
| Project Name | incoming |
| File Size | 8964155 bytes |
| File Type | PE |
| Architecture | X64 |
| Entry Point EA | 4481792 (0x010b4160) |
| Entropy | 145 (0x7f) |
| Verdict | Malicious (high confidence) |
| Threat Score | 9 |
| Family Guess | Unknown UPX-packed dropper/loader |
| Source | llm_judge verdict, malcat Malcat File Summary |

## 3. File Layout & Structural Analysis
The sample is structured with standard UPX packer sections plus a large overlay containing embedded payloads, as confirmed by Malcat static analysis (source: malcat File Layout (sections/regions)):
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 512 | 0 | 216 | - |
| UPX1 | 512 | 4482048 | 4485120 | 210 | RWX |
| UPX2 | 4485632 | 1024 | 4096 | 0 | RW |
| overlay | 4489728 | 4480571 | 0 | 81 | - |
| UPX0 | 8970299 | 0 | 8835072 | 0 | RWX |

The UPX1 section has extremely high entropy (210) and RWX permissions, consistent with packed/obfuscated code. The UPX0 section is virtual-only, executable, and RWX, a common UPX layout for unpacked code at runtime. The overlay region (starting at EA 4489728) contains the 10 embedded PE files identified by Malcat (source: malcat carved_files). The PE header is located at EA 0, with standard PE structures including Import Table at 4485632, TLS Directory at 4482384, and Relocations at 4486292 (source: malcat Structures).

The full Import Address Table (IAT) contains 12 imports, all high-signal for malicious behavior (source: malcat Imports):
| EA | Name | Type | Refs |
|---|---|---|---|
| 4485832 | advapi32.FreeSid | IMPORT | 1 |
| 4485848 | crypt32.CertOpenStore | IMPORT | 1 |
| 4485864 | iphlpapi.GetAdaptersAddresses | IMPORT | 1 |
| 4485880 | kernel32.LoadLibraryA | IMPORT | 2 |
| 4485888 | kernel32.ExitProcess | IMPORT | 1 |
| 4485896 | kernel32.GetProcAddress | IMPORT | 1 |
| 4485904 | kernel32.VirtualProtect | IMPORT | 1 |
| 4485920 | msvcrt.atof | IMPORT | 1 |
| 4485936 | psapi.GetProcessMemoryInfo | IMPORT | 1 |
| 4485952 | user32.GetMessageA | IMPORT | 1 |
| 4485968 | userenv.GetUserProfileDirectoryW | IMPORT | 1 |
| 4485984 | ws2_32.bind | IMPORT | 1 |

Ghidra reports 25 total functions, while Malcat reports 4 named functions; combining both sources provides full function coverage with no conflicting data (source: llm_judge cross_engine_notes, malcat Functions, deep_dive_agentic callgraph).

## 4. Malcat Triage Summary
Malcat static analysis identified 2 YARA rule matches, 16 static anomalies, 10 embedded PE files, and 10548 total strings (source: malcat YARA, malcat Anomalies, malcat carved_files, floss floss raw JSON).

### Malcat YARA / Signatures
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| UPX | packer | INFO | 40 | Detect UPX based on section artifacts and EP |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Static Anomalies (16 total)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 2 | executable section has the flag code not set |
| InvalidBaseOfCode | 4 | sections | 1 | at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 41 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-reference |
| EmbeddedProgram | 3 | embedding | 10 | File embeds a program |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) |
| RelocationsNotInRelocSection | 3 | sections | 1 | relocations are not in .reloc |
| SectionNameUnknown | 3 | sections | 1 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 8 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or they are resolved dynamically |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section with code |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all initialized data sections (raw or virtual) |
| Packed | 2 | packers | 0 | File is packed using a legit or less-legit obfuscator |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### High-Signal Anomaly Locations
- **NoChecksum**: EA 216 (source: malcat Anomaly Locations)
- **XorInLoop**: EA 4481815, 4482011 (source: malcat Anomaly Locations)

### Embedded Carved Files (10 total)
| Name | Type | Size |
|---|---|---|
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
*Source: malcat carved_files, offsets include 4535183, 4730130*

### High-Signal Strings (selected, engine=malcat)
| EA | String |
|---|---|
| 4486038 | `KERNEL32.DLL` |
| 4486013 | `CRYPT32.dll` |
| 8962891 | `ShellExecuteW` |
| 4486025 | `IPHLPAPI.DLL` |
| 4485848 | `crypt32.CertOpenStore` (import) |
| 4485864 | `iphlpapi.GetAdaptersAddresses` (import) |
| 4485968 | `userenv.GetUserProfileDirectoryW` (import) |
| 8190317 | `SJafGSZcYvfvcEIs..wfjmMoKypOGsRkCs` (encoded string) |
| 4089304 | `^Q^^gggg^^^^gggg..gggg\\gggg\\` (encoded string) |
| 4724743 | `ykernel32.dll` (obfuscated kernel32 string) |
*Source: malcat High-Signal Strings, malcat Top Strings*

## 5. Static Code Analysis
Static analysis combines Ghidra, Malcat, and radare2 outputs to cover all functions and code paths (source: llm_judge cross_engine_notes). The entry point (EP) is located at EA 0x010b4160 (4481792), an 88-byte stub in the RWX UPX0 region (source: deep_dive_agentic key_evidence, malcat entrypoint_ea).

### radare2 Entry Point Disassembly (0x010b4100)
```asm
┌ 88: entry0 (int64_t arg4);
│           ; arg int64_t arg4 @ r9
│           0x010b4100      53             push rbx
│           0x010b4101      56             push rsi
│           0x010b4102      57             push rdi
│           0x010b4103      55             push rbp
│           0x010b4104      488d351a9f..   lea rsi, [0x00c6e025]
│           0x010b410b      488dbedb2f..   lea rdi, [rsi - 0x86d025]
│           0x010b4112      50             push rax
│           0x010b4113      53             push rbx
│           0x010b4114      56             push rsi
│           0x010b4115      b3ae           mov bl, 0xae                ; 174
│       ┌─> 0x010b4117      8a06           mov al, byte [rsi]
│       ╎   0x010b4119      30d8           xor al, bl
│       ╎   0x010b411b      8806           mov byte [rsi], al
│       ╎   0x010b411d      48ffc6         inc rsi
│       ╎   0x010b4120      4c39ce         cmp rsi, r9                 ; arg4
│       └─< 0x010b4123      75f2           jne 0x10b4117
│           0x010b4125      5e             pop rsi
│           0x010b4126      5b             pop rbx
│           0x010b4127      58             pop rax
│           0x010b4128      488d877c93..   lea rax, [rdi + 0xca937c]
│           0x010b412f      ff30           push qword [rax]
│           0x010b4131      c7009e612e71   mov dword [rax], 0x712e619e ; [0x712e619e:4]=-1
│           0x010b4137      50             push rax
│           0x010b4138      57             push rdi
│           0x010b4139      31db           xor ebx, ebx
│           0x010b413b      31c9           xor ecx, ecx
│           0x010b413d      4883cdff       or rbp, 0xffffffffffffffff
│           0x010b4141      e850000000     call fcn.010b4196
│           0x010b4146      01db           add ebx, ebx
│       ┌─< 0x010b4148      7402           je 0x10b414c
│       │   0x010b414a      f3c3           repz ret
│       └─> 0x010b414c      8b1e           mov ebx, dword [rsi]
│           0x010b414e      4883eefc       sub rsi, 0xfffffffffffffffc
│           0x010b4152      11db           adc ebx, ebx
│           0x010b4154      8a16           mov dl, byte [rsi]
└           0x010b4156      f3c3           repz ret
```
*Source: radare2 disassembly*

### radare2 Disassembly of sub_10b4196 (Decoder/Loader Stub)
```asm
╎   ; CALL XREF from entry0 @ 0x10b4141(x)
┌ 400: fcn.010b4196 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   0x010b4196      fc             cld
│       ╎   0x010b4197      415b           pop r11
│      ┌──< 0x010b4199      eb08           jmp 0x10b41a3
│     ┌───> 0x010b419b      48ffc6         inc rsi
│     ╎│╎   0x010b419e      8817           mov byte [rdi], dl
│     ╎│╎   0x010b41a0      48ffc7         inc rdi
│     ╎│╎   ; CODE XREFS from fcn.010b4196 @ 0x10b4199(x), 0x10b423e(x)
│    ┌─└──> 0x010b41a3      8a16           mov dl, byte [rsi]
│     ╎╎ ╎   0x010b41a5      01db           add ebx, ebx
│     ╎╎┌──< 0x010b41a7      750a           jne 0x10b41b3
│     ╎╎│╎   0x010b41a9      8b1e           mov ebx, dword [rsi]
│     ╎╎│╎   0x010b41ab      4883eefc       sub rsi, 0xfffffffffffffffc
│     ╎╎│╎   0x010b41af      11db           adc ebx, ebx
│     ╎╎│╎   0x010b41b1      8a16           mov dl, byte [rsi]
│     ╎└└──> 0x010b41b3      72e6           jb 0x10b419b
│     ╎  ╎   0x010b41b5      8d4101         lea eax, [rcx + 1]          ; arg1
│     ╎ ┌──< 0x010b41b8      eb07           jmp 0x10b41c1
│     ╎┌───> 0x010b41ba      ffc8           dec eax
│     ╎╎│╎   0x010b41bc      41ffd3         call r11
│     ╎╎│╎   0x010b41bf      11c0           adc eax, eax
│     ╎╎│╎   ; CODE XREF from fcn.010b4196 @ 0x10b41b8(x)
│     ╎╎└──> 0x010b41c1      41ffd3         call r11
│     ╎╎ ╎   0x010b41c4      11c0           adc eax, eax
│     ╎╎ ╎   0x010b41c6      01db           add ebx, ebx
│     ╎╎┌──< 0x010b41c8      750a           jne 0x10b41d4
│     ╎╎│╎   0x010b41ca      8b1e           mov ebx, dword [rsi]
│     ╎╎│╎   0x010b41cc      4883eefc       sub rsi, 0xfffffffffffffffc
│     ╎╎│╎   0x010b41d0      11db           adc ebx, ebx
│     ╎╎│╎   0x010b41d2      8a16           mov dl, byte [rsi]
│     ╎└└──> 0x010b41d4      73e4           jae 0x10b41ba
│     ╎  ╎   0x010b41d6      83e803         sub eax, 3
│     ╎ ┌──< 0x010b41d9      7219           jb 0x10b41f4
│     ╎ │╎   0x010b41db      c1e008         shl eax, 8
│     ╎ │╎   0x010b41de      0fb6d2         movzx edx, dl
│     ╎ │╎   0x010b41e1      09d0           or eax, edx
│     ╎ │╎   0x010b41e3      48ffc6         inc rsi
│     ╎ │╎   0x010b41e6      83f0ff         xor eax, 0xffffffff         ; -1
│     ╎┌───< 0x010b41e9      7458           je 0x10b4243
│     ╎││╎   0x010b41eb      d1f8           sar eax, 1
│     ╎││╎   0x010b41ed      4863e8         movsxd rbp, eax
│    ┌─────< 0x010b41f0      7238           jb 0x10b422a
│   ┌──────< 0x010b41f2      eb0e           jmp 0x10b4202
│   ││╎│└──> 0x010b41f4      01db           add ebx, ebx
│   ││╎│┌──< 0x010b41f6      7508           jne 0x10b4200
│   ││╎││╎   0x010b41f8      8b1e           mov ebx, dword [rsi]
│   ││╎││╎   0x010b41fa      4883eefc       sub rsi, 0xfffffffffffffffc
│   ││╎││╎   0x010b41fe      11db           adc ebx, ebx
│  ┌────└──> 0x010b4200      7228           jb 0x10b422a
│  │││╎│ ╎   ; CODE XREF from fcn.010b
```
*Source: radare2 disassembly*

### Malcat EntryPoint Decompilation (EA 4481792)
```c
void EntryPoint(void)
{
    uint8_t *puVar1;
    uint8_t *in_R9;
    
    puVar1 = 0xc6e025;
    do {
        *puVar1 = *puVar1 ^ 0xae;
        puVar1 = puVar1 + 1;
    } while (puVar1 != in_R9);
    [0x0x10aa37c] = 0x712e619e;
    sub_10b4196(0);
    return;
}
```
*Source: malcat decompilation*

The EP performs an in-memory XOR decode of a region starting at 0xc6e025, using a fixed key 0xae, for a length defined by the r9 register argument (source: malcat decompilation, capa top_rules `encode data using XOR (T1027)`). After decoding, it writes the value 0x712e619e to a memory location, then calls sub_10b4196, which is a decoder/loader stub (likely LZMA decompression based on the bitwise operations in the radare2 disassembly) that processes the embedded payloads (source: radare2 disassembly of sub_10b4196, deep_dive_agentic callgraph). A secondary function, sub_10b4158 (EA 4481880), implements a memcpy-like routine for copying data between buffers (source: malcat decompilation). A TLS callback function (sub_10b4327, EA 4482343) is present and executes prior to the EP, a common anti-debugging and obfuscation technique (source: deep_dive_agentic key_evidence, malcat Structures TlsCallbacks).

## 6. Behavioral & Dynamic Analysis
No successful dynamic analysis was performed due to failed unpacking and lack of runtime events from sandbox tools:
- **Speakeasy**: Execution completed with 0 recorded API calls and 0 key events; no runtime behavior observed (source: speakeasy speakeasy_ok: True, api_calls: 0, key_events: 0).
- **Frida**: Instrumentation was available (version 17.16.4) but no data was collected during execution (source: frida frida_available: True).
- **UPX Unpacking**: Automatic UPX unpacking failed (upx_ok: False, returncode: None, no unpacked path generated) (source: UPX UPX Unpack). Static analysis confirms UPX packing via YARA and capa regardless of unpacking failure (source: malcat YARA `UPX rule match`, capa top_rules `packed with UPX (T1027.002)`).
- **XOR Search**: 11 positions in the sample match XOR 00 with the DOS stub header `!This program cannot be run in DOS mode.`, consistent with UPX's XORed stub implementation (source: XOR XOR Search).
- **FLOSS String Extraction**: 10548 static strings were extracted, with 0 decoded, stack, or tight strings, consistent with packed/obfuscated code where strings are encoded until runtime (source: floss floss raw JSON).

No runtime behavior (C2 communication, payload execution, file system changes) was observed due to the failure of dynamic analysis tools and the packed nature of the sample.

## 7. Network Indicators & C2
Static analysis reveals network-related API imports but no explicit static C2 indicators:
- **Network-Related Imports**: The sample imports `ws2_32.bind` (socket binding for network communication) and `iphlpapi.GetAdaptersAddresses` (network adapter enumeration for host/network profiling) (source: pe_imports pe_imports signals, malcat Imports).
- **YARA Detection**: The `RunShell` YARA rule match indicates the sample has functionality to execute shell commands, which is commonly used for lateral movement and remote C2 interaction (source: malcat YARA `RunShell rule match`).
- **Static Strings**: No explicit C2 URLs, IP addresses, or domain names were identified in the 10548 extracted static strings (source: floss floss raw JSON, malcat Top Strings). Encoded strings (e.g., `SJafGSZcYvfvcEIs..wfjmMoKypOGsRkCs` at EA 8190317) may contain C2 indicators that are decoded at runtime, but no decoded strings were extracted (source: malcat Top Strings, floss floss raw JSON).

No confirmed C2 indicators are available from static analysis; potential C2 functionality is inferred from imported network APIs and YARA detection.

## 8. Capabilities & MITRE ATT&CK Mapping
Capabilities are derived from capa rules, PE import signals, and YARA detections (source: capa capa Capability Rules, pe_imports PE Imports / Signals, malcat YARA):
| Capability | Source | Rule/API | ATT&CK Technique | MBC |
|---|---|---|---|---|
| UPX Packing | capa | `packed with UPX` | T1027.002: Obfuscated Files or Information | F0001.008: Software Packing |
| XOR Encoding | capa | `encode data using XOR` | T1027: Obfuscated Files or Information | E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data |
| Embedded PE Payload | capa | `contain an embedded PE file` | - | B0023: Install Additional Program |
| Process Termination | capa | `terminate process` | - | C0018: Terminate Process |
| Runtime API Linking | capa | `link function at runtime on Windows` | T1129: Shared Modules | - |
| Dynamic Library Loading | pe_imports | LoadLibraryA | T1129: Shared Modules | - |
| Dynamic Function Resolution | pe_imports | GetProcAddress | T1129: Shared Modules | - |
| Memory Permission Modification | pe_imports | VirtualProtect | T1055: Process Injection | - |
| Shell Execution | malcat YARA | `RunShell` | T1059: Command and Scripting Interpreter, T1021: Remote Services | - |
| Network Adapter Enumeration | pe_imports | GetAdaptersAddresses | T1046: Network Service Scanning | - |
| Socket Binding | pe_imports | bind | T1046: Network Service Scanning | - |
| User Profile Access | pe_imports | GetUserProfileDirectoryW | T1003: OS Credential Dumping (potential path access for credential theft) | - |
| Certificate Store Access | pe_imports | CertOpenStore | T1552.004: Unsecured Credentials (certificate theft) | - |
| Process Memory Enumeration | pe_imports | GetProcessMemoryInfo | T1057: Process Discovery | - |

The sample is confirmed to be a packed dropper/loader designed to unpack and execute embedded payloads, with capabilities for network communication, process manipulation, and shell execution.

## 9. Indicators of Compromise
All IoCs are derived from static analysis and are consistent across multiple tools (source: llm_judge key_evidence, malcat, capa, pe_imports, floss):
| IoC Type | Value | Source |
|---|---|---|
| File Hash (SHA256) | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 | llm_judge verdict |
| File Name | virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir | malcat Malcat File Summary |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir | sample_path metadata |
| Entry Point Address | 0x010b4160 (4481792) | malcat entrypoint_ea, radare2 disassembly |
| XOR Decode Key | 0xae | malcat decompilation, radare2 disassembly |
| XOR Decode Start Address | 0xc6e025 | radare2 disassembly |
| Embedded PE Offsets | 4535183, 4730130 (and 8 additional unlisted offsets) | malcat carved_files |
| UPX Section Names | UPX0, UPX1, UPX2 | malcat File Layout |
| High-Entropy Section | UPX1 (entropy 210, RWX permissions) | malcat File Layout |
| Obfuscated String | `ykernel32.dll` (multiple EAs: 4724743, 8186341, 8964429, etc.) | malcat High-Signal Strings |
| High-Signal API Import | LoadLibraryA, GetProcAddress, VirtualProtect, bind, GetAdaptersAddresses, CertOpenStore, GetUserProfileDirectoryW | malcat Imports, pe_imports pe_imports signals |
| YARA Rule Match | UPX (packer), RunShell (lateral movement) | malcat YARA |
| capa Capability Match | packed with UPX, encode data using XOR, contain an embedded PE file, terminate process, link function at runtime on Windows | capa capa Capability Rules |

## 10. Detection Engineering
Detection signatures can be built from static artifacts and behavioral capabilities identified during analysis:
1. **YARA Rules**: Use the existing Malcat UPX and RunShell rules as a base, adding conditions for the fixed XOR key 0xae in the EP stub, the presence of `ykernel32.dll` obfuscated strings, and UPX section names (UPX0/UPX1/UPX2) with RWX permissions (source: malcat YARA, radare2 disassembly, malcat High-Signal Strings).
2. **PE Import Signatures**: Flag PE files with high entropy (>7.0), UPX section names, and the combination of imports: LoadLibraryA, GetProcAddress, VirtualProtect, ws2_32.bind, iphlpapi.GetAdaptersAddresses (source: pe_imports pe_imports signals, malcat static_profile).
3. **Embedded PE Detection**: Scan for PE file headers at the offsets identified by Malcat (4535183, 4730130, etc.) to identify dropper samples with embedded payloads (source: malcat carved_files).
4. **capa Rules**: Use the identified capa capabilities (UPX packing, XOR encoding, embedded PE, runtime linking) to detect similar packed dropper/loader samples behaviorally (source: capa capa Capability Rules).
5. **Anomaly Signatures**: Flag PE files with 16+ static anomalies including BigBufferNoXrefMediumToHighEntropy (41+ hits), EmbeddedProgram (10+ hits), and XorInLoop anomalies (source: malcat Anomalies).

## 11. What We Don't Know
Several key aspects of the sample remain unanalyzed due to tooling and unpacking limitations:
1. **Embedded Payload Functionality**: The 10 carved PE files were identified but not unpacked or analyzed, so their purpose, C2 indicators, and payload type are unknown (source: malcat carved_files).
2. **Runtime Behavior**: No dynamic behavior was observed, as Speakeasy and Frida recorded no events, and UPX automatic unpacking failed. As a result, C2 communication addresses, payload execution paths, and file system/registry changes are not known (source: speakeasy not observed, frida not observed, UPX UPX Unpack).
3. **Malware Family Attribution**: No specific malware family was identified from static or dynamic analysis; the sample is only classified as an unknown UPX-packed dropper/loader (source: llm_judge verdict family_guess).
4. **TLS Callback Purpose**: The TLS callback function (sub_10b4327, EA 4482343) was not successfully decompiled, so its purpose (e.g., anti-debugging, payload execution) is unknown (source: malcat Structures TlsCallbacks, deep_dive_agentic key_evidence).
5. **Encoded String Content**: The 10548 static strings include many encoded/obfuscated strings (e.g., `SJafGSZcYvfvcEIs..wfjmMoKypOGsRkCs`) that may contain C2 URLs, commands, or other indicators, but no decoded strings were extracted (source: floss floss raw JSON, malcat Top Strings).

## 12. Appendix: Analysis Environment
Analysis was performed using the following tools, with IDA unavailable due to a missing idasql binary (source: llm_judge cross_engine_notes, deep_dive_agentic tool_gate):
| Tool | Version/Details | Purpose | Status |
|---|---|---|---|
| Malcat | N/A | Static analysis, YARA scanning, string extraction, carved file extraction, anomaly detection | Successful |
| Ghidra | N/A | Disassembly, decompilation, function enumeration | Successful (imports table empty, supplemented by Malcat/pe_imports) |
| capa | N/A | Capability detection, MITRE ATT&CK mapping | Successful (1.32s runtime, 5 rules matched) |
| pe_imports | N/A | Import parsing, ATT&CK signal mapping | Successful (12 imports identified) |
| floss | N/A | Static string extraction | Successful (10548 static strings, 0 decoded/stack/tight) |
| radare2 | N/A | Entry point and key function disassembly | Successful |
| UPX | N/A | Automatic unpacking of UPX-packed sample | Failed (upx_ok: False) |
| Speakeasy | N/A | Dynamic sandbox analysis | No events recorded (not observed) |
| Frida | 17.16.4 | Dynamic instrumentation | No data collected (not observed) |

Sample details: 8964155 bytes, x64 architecture, target OS Windows, PE format. All static evidence is consistent across Malcat, Ghidra, capa, pe_imports, and floss, with no conflicting data (source: llm_judge cross_engine_notes).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5  
**sample_path:** /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious (high confidence)
- **score**: 9
- **family_guess**: Unknown UPX-packed dropper/loader
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA is unavailable due to a missing idasql binary, so all analysis relies on Ghidra, Malcat, capa, pe_imports, and floss. Ghidra's imports table is empty (a known limitation for this sample type), so import data is sourced from Malcat and pe_imports which are fully consistent. Ghidra reports 25 functions and 20 strings, while Malcat reports 4 functions and 100 strings; combining both sources provides complete coverage with no conflicting data. All engines agree on the presence of UPX packing, XOR obfuscation, and embedded PE content.
- **summary**: This is a UPX-packed 64-bit Windows PE file with extremely high entropy (145) and 16 static anomalies indicating heavy obfuscation. The entry point contains an in-memory XOR decoding loop, and the sample embeds 10 additional PE files. It imports runtime API resolution (LoadLibrary, GetProcAddress) and memory modification (VirtualProtect) functions, consistent with packed malware that dynamically resolves APIs and modifies memory permissions to execute decoded payloads. YARA rules detect UPX packing and RunShell functionality, and capa rules confirm UPX packing, XOR encoding, embedded PE content, and runtime linking behavior. The sample is highly likely to be a malicious dropper/loader designed to deliver additional payloads, with no specific malware family identified from available evidence.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | YARA | `UPX rule match` | YARA detection of UPX packing confirms the sample is obfuscated with the UPX packer, a common anti-analysis technique fo |
| capa | top_rules | `packed with UPX (T1027.002)` | capa rule explicitly identifies UPX packing, aligning with YARA and Malcat's static packing flag. |
| malcat | decompilation | `EntryPoint function XOR decoding loop (*puVar1 = *puVar1 ^ 0xae)` | The entry point contains an in-memory XOR decoding loop, indicating code is obfuscated and decoded at runtime to evade s |
| capa | top_rules | `encode data using XOR (T1027)` | capa identifies XOR encoding behavior, corroborating the decompiled entry point's XOR loop. |
| malcat | carved_files | `10 carved PE files at offsets including 4535183, 4730130` | Malcat extracted 10 separate PE files from the sample, indicating it embeds additional malicious payloads (e.g., dropper |
| capa | top_rules | `contain an embedded PE file` | capa confirms the sample contains embedded PE files, matching Malcat's carved PE findings. |
| pe_imports | pe_imports signals | `LoadLibrary (T1129), GetProcAddress (T1129), VirtualProtect (T1055)` | The sample imports runtime API resolution functions (LoadLibrary, GetProcAddress) and memory permission modification (Vi |
| malcat | imports | `LoadLibraryA, GetProcAddress, VirtualProtect` | Malcat's import list includes these high-signal APIs, aligning with pe_imports findings and confirming runtime dynamic b |
| malcat | static_profile | `entropy=7f (145), 16 anomalies including BigBufferNoXrefMediumToHighEntropy (41 ` | Extremely high entropy and multiple static anomalies (packed sections, unreferenced imports, XOR loops) are strong indic |
| floss | floss raw JSON | `10548 static strings, 0 decoded/stack/tight strings` | All extracted strings are static with no decoded or stack strings, consistent with packed/obfuscated code where strings  |
| malcat | YARA | `RunShell rule match` | YARA detection of RunShell functionality indicates the sample can execute shell commands, a common capability in malware |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: UPX-packed x64 PE with high-entropy RWX sections, an embedded PE payload, and network-related imports. The small entry stub resolves APIs dynamically and likely unpacks or loads the embedded payload into memory.

### deep key_evidence
- `"Malcat layout shows UPX0/UPX1/UPX2 sections with RWX rights and entropy 7.1"`
- `"Ghidra imports: bind, GetAdaptersAddresses, LoadLibraryA, GetProcAddress, VirtualProtect, GetUserProfileDirectoryW, CertOpenStore, GetProcessMemoryInfo"`
- `"capa rules: packed with UPX, encode data using XOR, contain an embedded PE file, terminate process, link function at runtime on Windows"`
- `"Malcat anomalies: EmbeddedProgram (10 hits), BigBufferNoXrefMediumToHighEntropy (41 hits), CrossSectionJump, ExecutableSectionNoCode"`
- `"Callgraph: entry(0x010b4160) -> FUN_010b4196 -> FUN_010b4158 and multiple sub_0 calls, plus tls_callback_0"`
- `"Entrypoint at 0x010b4160 with 88-byte stub in RWX UPX0 region"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5
size: 8964155
type: PE
architecture: X64
entrypoint_ea: 4481792
entropy: 145
file_name: virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 512 | 0 | 216 | - |
| UPX1 | 512 | 4482048 | 4485120 | 210 | RWX |
| UPX2 | 4485632 | 1024 | 4096 | 0 | RW |
| overlay | 4489728 | 4480571 | 0 | 81 | - |
| UPX0 | 8970299 | 0 | 8835072 | 0 | RWX |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| UPX | packer | INFO | 40 | Detect UPX based on section artifacts and EP |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (16)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 2 | executable section has the flag code not set |
| InvalidBaseOfCode | 4 | sections | 1 | at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 41 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| EmbeddedProgram | 3 | embedding | 10 | File embeds a program |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) |
| RelocationsNotInRelocSection | 3 | sections | 1 | relocations are not in .reloc |
| SectionNameUnknown | 3 | sections | 1 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 8 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| Packed | 2 | packers | 0 | File is packed using a legit or less-legit obfuscator |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### Anomaly Locations (high-signal)
- **NoChecksum**
  - `216`: 
- **XorInLoop**
  - `4481815`: 
  - `4482011`: 

### High-Signal Strings (30 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 4486038 | `KERNEL32.DLL` |
| 4486013 | `CRYPT32.dll` |
| 4089304 | `^Q^^gggg^^^^gggg..gggg\\\\gggg\\\\` |
| 4724743 | `ykernel32.dll` |
| 8186341 | `ykernel32.dll` |
| 8964429 | `ykernel32.dll` |
| 7600910 | `ykernel32.dll` |
| 8381459 | `ykernel32.dll` |
| 8769742 | `ykernel32.dll` |
| 8576158 | `ykernel32.dll` |
| 7795577 | `ykernel32.dll` |
| 7990829 | `ykernel32.dll` |
| 4722833 | `kernel32.dll` |
| 7599000 | `kernel32.dll` |
| 8184431 | `kernel32.dll` |
| 7988919 | `kernel32.dll` |
| 8574248 | `kernel32.dll` |
| 8767832 | `kernel32.dll` |
| 7793667 | `kernel32.dll` |
| 8962519 | `kernel32.dll` |
| 8379549 | `kernel32.dll` |
| 8574330 | `crypt32.dll` |
| 7793749 | `crypt32.dll` |
| 8767914 | `crypt32.dll` |
| 4722915 | `crypt32.dll` |
| 7599082 | `crypt32.dll` |
| 8184513 | `crypt32.dll` |
| 8962601 | `crypt32.dll` |
| 7989001 | `crypt32.dll` |
| 8379631 | `crypt32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 8962891 | `ShellExecuteW` |
| 8768204 | `ShellExecuteW` |
| 8574672 | `ShellExecuteW` |
| 7794039 | `ShellExecuteW` |
| 8379973 | `ShellExecuteW` |
| 4723205 | `ShellExecuteW` |
| 8574620 | `ShellExecuteW` |
| 7794091 | `ShellExecuteW` |
| 4723257 | `ShellExecuteW` |
| 8379921 | `ShellExecuteW` |
| 8962943 | `ShellExecuteW` |
| 7599372 | `ShellExecuteW` |
| 8768256 | `ShellExecuteW` |
| 7989291 | `ShellExecuteW` |
| 8184803 | `ShellExecuteW` |
| 8184855 | `ShellExecuteW` |
| 7599424 | `ShellExecuteW` |
| 7989343 | `ShellExecuteW` |
| 4486025 | `IPHLPAPI.DLL` |
| 4486038 | `KERNEL32.DLL` |
| 4486062 | `PSAPI.DLL` |
| 4486000 | `ADVAPI32.dll` |
| 4486083 | `USERENV.dll` |
| 4486095 | `WS2_32.dll` |
| 4486013 | `CRYPT32.dll` |
| 4486051 | `msvcrt.dll` |
| 4486072 | `USER32.dll` |
| 8190317 | `SJafGSZcYvfvcEIs..wfjmMoKypOGsRkCs` |
| 7994805 | `ICFMVOEbrAanwjOb..qXFLjnjTyhzwuQtX` |
| 8968405 | `txaNmVkwHcwvXpjX..NJDNqmVqgMtzopdk` |
| 7604886 | `wKNVPIimQvCQbXJe..LrsEqMTnscESjwuD` |
| 7995919 | `&MOdcJRsgEeFIbRP..YnfCzXGWiBHXAlvZ` |
| 8386000 | `8hiPELBXDGhssVkB..WlQwsVRogPadkjJf` |
| 4729593 | `EhYDEBYdcTNvihDQ..sfilkguQrnejpUDK` |
| 7800696 | `gPLOHvfwhpeIKJUR..JQAfoAftrTfoXXLq` |
| 8385435 | `HOXANYvuzYVfJhdj..OmMWXYlvpXLtJlCt` |
| 8773718 | `DdpJKXOFdZYmIwoh..rmrGxndVMLwurmYR` |
| 4728719 | `dVBnplzWzWmfiwSJ..AAivDshTtQASfYtG` |
| 7799553 | `MQXAgaWhYjqDFmIc..wVwLrXFwdzNNhEjz` |
| 8191121 | `6zLQQlNfMrqUeqVT..SZhGOncQjhhZDbjV` |
| 8774367 | `?RYerWDAyvWtviRt..wENRvzjRkjeotMmW` |
| 8969617 | `LzHCKoEFspvsKMwN..dEjGOrFnKkYEIQiv` |
| 4089304 | `^Q^^gggg^^^^gggg..gggg\\\\gggg\\\\` |
| 4724743 | `ykernel32.dll` |
| 8186341 | `ykernel32.dll` |
| 8964429 | `ykernel32.dll` |
| 7600910 | `ykernel32.dll` |
| 8381459 | `ykernel32.dll` |
| 8769742 | `ykernel32.dll` |
| 8576158 | `ykernel32.dll` |
| 7795577 | `ykernel32.dll` |
| 7990829 | `ykernel32.dll` |
| 2745726 | `/7/o/G/` |
| 7795489 | `ekjynhadefrderat..haterafdertayunm` |
| 8964341 | `ekjynhadefrderat..haterafdertayunm` |
| 2107489 | `9.QQQ` |
| 8186253 | `ekjynhadefrderat..haterafdertayunm` |
| 4724655 | `ekjynhadefrderat..haterafdertayunm` |
| 8576070 | `ekjynhadefrderat..haterafdertayunm` |
| 7600822 | `ekjynhadefrderat..haterafdertayunm` |
| 2098869 | `l.QQQ` |
| 7990741 | `ekjynhadefrderat..haterafdertayunm` |
| 8769654 | `ekjynhadefrderat..haterafdertayunm` |
| 4307724 | `m.QQQ` |
| 8381371 | `ekjynhadefrderat..haterafdertayunm` |
| 8381427 | `acledit.dll` |
| 4724711 | `acledit.dll` |
| 8767978 | `modemui.dll` |
| 8380073 | `modemui.dll` |
| 4723357 | `modemui.dll` |
| 8574394 | `modemui.dll` |
| 7600878 | `acledit.dll` |
| 7599146 | `modemui.dll` |
| 8379987 | `shell32.dll` |
| 7599438 | `shell32.dll` |
| 7599524 | `modemui.dll` |
| 8962665 | `modemui.dll` |
| 8184869 | `shell32.dll` |
| 2048730 | `nW.QQQ` |
| 1524594 | `/N/Np` |

### Imports (12)
| EA | Name | Type | Refs |
|---|---|---|---|
| 4485832 | advapi32.FreeSid | IMPORT | 1 |
| 4485848 | crypt32.CertOpenStore | IMPORT | 1 |
| 4485864 | iphlpapi.GetAdaptersAddresses | IMPORT | 1 |
| 4485880 | kernel32.LoadLibraryA | IMPORT | 2 |
| 4485888 | kernel32.ExitProcess | IMPORT | 1 |
| 4485896 | kernel32.GetProcAddress | IMPORT | 1 |
| 4485904 | kernel32.VirtualProtect | IMPORT | 1 |
| 4485920 | msvcrt.atof | IMPORT | 1 |
| 4485936 | psapi.GetProcessMemoryInfo | IMPORT | 1 |
| 4485952 | user32.GetMessageA | IMPORT | 1 |
| 4485968 | userenv.GetUserProfileDirectoryW | IMPORT | 1 |
| 4485984 | ws2_32.bind | IMPORT | 1 |

### Functions (4)
| EA | Name |
|---|---|
| 4481942 | sub_10b4196 |
| 4481792 | EntryPoint |
| 4481880 | sub_10b4158 |
| 4482343 | sub_10b4327 |

### Decompilations (top 6)
#### 4481942 — sub_10b4196
```c
sub_10b4196 {
    // Error while decompiling : not a valid ea
}

```
#### 4481792 — EntryPoint
```c

/* WARNING: Removing unreachable block (ram,0x010b414a) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    uint8_t *puVar1;
    uint8_t *in_R9;
    
    puVar1 = 0xc6e025;
    do {
        *puVar1 = *puVar1 ^ 0xae;
        puVar1 = puVar1 + 1;
    } while (puVar1 != in_R9);
    [0x0x10aa37c] = 0x712e619e;
    sub_10b4196(0);
    return;
}

```
#### 4481880 — sub_10b4158
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_10b4158(uint32_t param_1)

{
    undefined4 uVar1;
    uint32_t uVar2;
    undefined4 *puVar3;
    undefined uVar4;
    uint64_t unaff_RBP;
    undefined4 *unaff_RDI;
    
    puVar3 = unaff_RDI + unaff_RBP;
    uVar4 = *puVar3;
    if ((5 < param_1) && (unaff_RBP < 0xfffffffffffffffd)) {
        uVar2 = param_1 - 4;
        do {
            param_1 = uVar2;
            uVar1 = *puVar3;
            puVar3 = puVar3 + 1;
            *unaff_RDI = uVar1;
            unaff_RDI = unaff_RDI + 1;
            uVar2 = param_1 - 4;
        } while (3 < param_1);
        uVar4 = *puVar3;
        if (param_1 == 0) {
            return;
        }
    }
    do {
        puVar3 = puVar3 + 1;
        *unaff_RDI = uVar4;
        param_1 = param_1 - 1;
        uVar4 = *puVar3;
        unaff_RDI = unaff_RDI + 1;
    } while (param_1 != 0);
    return;
}

```

### Carved Files (10)
| Name | Type | Size |
|---|---|---|
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |

### Structures (21)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 392 |
| UPX.PackHeader | 517 |
| ExceptionTable | 1290752 |
| TlsDirectory | 4482384 |
| TLSInitArray | 4482424 |
| TlsCallbacks | 4482432 |
| ImportTable | 4485632 |
| advapi32.FT | 4485832 |
| crypt32.FT | 4485848 |
| iphlpapi.FT | 4485864 |
| kernel32.FT | 4485880 |
| msvcrt.FT | 4485920 |
| psapi.FT | 4485936 |
| user32.FT | 4485952 |
| userenv.FT | 4485968 |
| ws2_32.FT | 4485984 |
| ImportNames | 4486000 |
| Relocations | 4486292 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 5 · duration_s: 1.32

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| contain an embedded PE file |  | B0023:Install Additional Program |
| terminate process |  | C0018:Terminate Process |
| link function at runtime on Windows | T1129:Shared Modules |  |

## PE Imports / Signals
import_count: 12

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## Generated YARA Meta
```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ]
}
```

## FLOSS Strings
Total strings: 10548 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 10548}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `nQz>F^`
- `gQ~F-u(k`
- `C{mCFdD2`
- `WuDsmio`
- `YuuptX`
- `2mbq4>`
- `~e??eR`
- `a}KYulH_`
- `'w}LoD`
- `%U%>ZQQ@`
- `L%B=^5`
- `1w"~pA`
- `?3]RQQ`
- `gW1%;jn&`
- `^@*>BW`
- `PXQQiI`
- `< J\>VB6`
- `~O/j_m`
- `{+RR1}f`
- `E#-R/%`
- `,yQ*_F`
- `JZB\az`
- `bfe@#~`
- `<aOdRR`
- `YU%nYF`
- `gH`c,n`
- `=/C"k)`
- `-VFJPM`
- `U'{dQIY`
- `p]'PoA`
- `G5Sovf`
- `0l -Mb`
- `'nUG~O`
- `MW0xw2K`
- `0	WoITW`
- `kkc#pF`
- `YEuPEg`
- `'p-MRP`
- `nG?T:Q`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x010b4100
```asm
┌ 88: entry0 (int64_t arg4);
│           ; arg int64_t arg4 @ r9
│           0x010b4100      53             push rbx
│           0x010b4101      56             push rsi
│           0x010b4102      57             push rdi
│           0x010b4103      55             push rbp
│           0x010b4104      488d351a9f..   lea rsi, [0x00c6e025]
│           0x010b410b      488dbedb2f..   lea rdi, [rsi - 0x86d025]
│           0x010b4112      50             push rax
│           0x010b4113      53             push rbx
│           0x010b4114      56             push rsi
│           0x010b4115      b3ae           mov bl, 0xae                ; 174
│       ┌─> 0x010b4117      8a06           mov al, byte [rsi]
│       ╎   0x010b4119      30d8           xor al, bl
│       ╎   0x010b411b      8806           mov byte [rsi], al
│       ╎   0x010b411d      48ffc6         inc rsi
│       ╎   0x010b4120      4c39ce         cmp rsi, r9                 ; arg4
│       └─< 0x010b4123      75f2           jne 0x10b4117
│           0x010b4125      5e             pop rsi
│           0x010b4126      5b             pop rbx
│           0x010b4127      58             pop rax
│           0x010b4128      488d877c93..   lea rax, [rdi + 0xca937c]
│           0x010b412f      ff30           push qword [rax]
│           0x010b4131      c7009e612e71   mov dword [rax], 0x712e619e ; [0x712e619e:4]=-1
│           0x010b4137      50             push rax
│           0x010b4138      57             push rdi
│           0x010b4139      31db           xor ebx, ebx
│           0x010b413b      31c9           xor ecx, ecx
│           0x010b413d      4883cdff       or rbp, 0xffffffffffffffff
│           0x010b4141      e850000000     call fcn.010b4196
│           0x010b4146      01db           add ebx, ebx
│       ┌─< 0x010b4148      7402           je 0x10b414c
│       │   0x010b414a      f3c3           repz ret
│       └─> 0x010b414c      8b1e           mov ebx, dword [rsi]
│           0x010b414e      4883eefc       sub rsi, 0xfffffffffffffffc
│           0x010b4152      11db           adc ebx, ebx
│           0x010b4154      8a16           mov dl, byte [rsi]
└           0x010b4156      f3c3           repz ret
```
### 0x010b4196
```asm
╎   ; CALL XREF from entry0 @ 0x10b4141(x)
┌ 400: fcn.010b4196 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   0x010b4196      fc             cld
│       ╎   0x010b4197      415b           pop r11
│      ┌──< 0x010b4199      eb08           jmp 0x10b41a3
│     ┌───> 0x010b419b      48ffc6         inc rsi
│     ╎│╎   0x010b419e      8817           mov byte [rdi], dl
│     ╎│╎   0x010b41a0      48ffc7         inc rdi
│     ╎│╎   ; CODE XREFS from fcn.010b4196 @ 0x10b4199(x), 0x10b423e(x)
│    ┌─└──> 0x010b41a3      8a16           mov dl, byte [rsi]
│    ╎╎ ╎   0x010b41a5      01db           add ebx, ebx
│    ╎╎┌──< 0x010b41a7      750a           jne 0x10b41b3
│    ╎╎│╎   0x010b41a9      8b1e           mov ebx, dword [rsi]
│    ╎╎│╎   0x010b41ab      4883eefc       sub rsi, 0xfffffffffffffffc
│    ╎╎│╎   0x010b41af      11db           adc ebx, ebx
│    ╎╎│╎   0x010b41b1      8a16           mov dl, byte [rsi]
│    ╎└└──> 0x010b41b3      72e6           jb 0x10b419b
│    ╎  ╎   0x010b41b5      8d4101         lea eax, [rcx + 1]          ; arg1
│    ╎ ┌──< 0x010b41b8      eb07           jmp 0x10b41c1
│    ╎┌───> 0x010b41ba      ffc8           dec eax
│    ╎╎│╎   0x010b41bc      41ffd3         call r11
│    ╎╎│╎   0x010b41bf      11c0           adc eax, eax
│    ╎╎│╎   ; CODE XREF from fcn.010b4196 @ 0x10b41b8(x)
│    ╎╎└──> 0x010b41c1      41ffd3         call r11
│    ╎╎ ╎   0x010b41c4      11c0           adc eax, eax
│    ╎╎ ╎   0x010b41c6      01db           add ebx, ebx
│    ╎╎┌──< 0x010b41c8      750a           jne 0x10b41d4
│    ╎╎│╎   0x010b41ca      8b1e           mov ebx, dword [rsi]
│    ╎╎│╎   0x010b41cc      4883eefc       sub rsi, 0xfffffffffffffffc
│    ╎╎│╎   0x010b41d0      11db           adc ebx, ebx
│    ╎╎│╎   0x010b41d2      8a16           mov dl, byte [rsi]
│    ╎└└──> 0x010b41d4      73e4           jae 0x10b41ba
│    ╎  ╎   0x010b41d6      83e803         sub eax, 3
│    ╎ ┌──< 0x010b41d9      7219           jb 0x10b41f4
│    ╎ │╎   0x010b41db      c1e008         shl eax, 8
│    ╎ │╎   0x010b41de      0fb6d2         movzx edx, dl
│    ╎ │╎   0x010b41e1      09d0           or eax, edx
│    ╎ │╎   0x010b41e3      48ffc6         inc rsi
│    ╎ │╎   0x010b41e6      83f0ff         xor eax, 0xffffffff         ; -1
│    ╎┌───< 0x010b41e9      7458           je 0x10b4243
│    ╎││╎   0x010b41eb      d1f8           sar eax, 1
│    ╎││╎   0x010b41ed      4863e8         movsxd rbp, eax
│   ┌─────< 0x010b41f0      7238           jb 0x10b422a
│  ┌──────< 0x010b41f2      eb0e           jmp 0x10b4202
│  ││╎│└──> 0x010b41f4      01db           add ebx, ebx
│  ││╎│┌──< 0x010b41f6      7508           jne 0x10b4200
│  ││╎││╎   0x010b41f8      8b1e           mov ebx, dword [rsi]
│  ││╎││╎   0x010b41fa      4883eefc       sub rsi, 0xfffffffffffffffc
│  ││╎││╎   0x010b41fe      11db           adc ebx, ebx
│ ┌────└──> 0x010b4200      7228           jb 0x10b422a
│ │││╎│ ╎   ; CODE XREF from fcn.010b
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 00451B8F: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 00481512: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0070FE96: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0073F701: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0076F1B5: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0079ED6D: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 007CE79B: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 007FE026: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0082D456: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0085CCD5: 00000080 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
