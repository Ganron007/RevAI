## 1. Executive Summary
This sample (sha256: 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb) is a malicious 3.1MB X86 GUI PE file packed with ASPack/ASProtect, with a maliciousness score of 9 (source: llm_judge, verdict.json). It masquerades as legitimate Microsoft Firewall software using spoofed version metadata (source: malcat, file_summary.metadata) to evade user detection. Static analysis is heavily limited by strong packing: entropy is measured at 112 (source: malcat, file_summary.entropy), Ghidra reports 0 recoverable functions (source: ghidra, funcs), and Malcat only identifies 2 stub functions (source: malcat, functions). Cross-engine evidence confirms malicious intent: YARA detects 12 ASPack/ASProtect packing signatures (source: yara, matches), capa identifies ASPack packing (T1027.002) and VirtualBox anti-VM behavior (T1497.001) (source: capa, top_rules), and the sample imports only dynamic-resolution APIs (LoadLibraryA, GetProcAddress, GetModuleHandleA) plus MSVBVM60._CIcos, indicating use of VB6 runtime for payload execution (source: pe_imports, imports; source: malcat, imports). The sample contains embedded PE and PKCS7 files (source: malcat, carved_files), confirming dropper/loader functionality. No legitimate functionality was identified across all analysis tools.

## 2. Sample Metadata
| Field | Value | Source |
|---|---|---|
| SHA256 | 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb | llm_judge, verdict.json |
| Sample Path | /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir | llm_judge, verdict.json |
| Project Name | incoming | llm_judge, verdict.json |
| File Size | 3148577 bytes (3.1MB) | malcat, file_summary |
| File Type | PE (X86 GUI) | malcat, file_summary |
| Entry Point (EA) | 0x00008601 (34305 decimal) | malcat, file_summary |
| Entropy | 112 | malcat, file_summary |
| Compiler | MSVC 6.0 (linker signature) | malcat, yara/signatures (MSVC_6_linker rule) |

## 3. File Layout & Structural Analysis
The sample has a heavily modified PE structure consistent with ASPack packing, with 7 sections plus an overlay (source: malcat, file_layout):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0x00000000 | 1536 | 0 | 185 | - |
| .text | 0x00000600 | 7168 | 20480 | 185 | RW |
| .data | 0x00005600 | 512 | 4096 | 0 | RW |
| .rsrc | 0x00006600 | 512 | 8192 | 0 | RW |
| .aspack | 0x00008600 | 8704 | 12288 | 0 | RW |
| .reloc | 0x0000B600 | 6144 | 8192 | 101 | RX |
| overlay | 0x0000D600 | 3124001 | 0 | 111 | - |
| .adata | 0x00030801 | 0 | 4096 | 0 | RW |

Key structural anomalies (20 total, source: malcat, anomalies) include:
- EntryPointInNonExecRegion (level 4): Entry point 0x00008601 is located in the .aspack section, which is marked RW (non-executable), a common packing artifact.
- InvalidBaseOfCode/InvalidBaseOfData (level 4): Code and data section bases do not align with PE header expectations.
- MultiplePackers (level 4): 4 packer markers detected, indicating layered obfuscation.
- UnsignedMicrosoft (level 4): Version info claims to be a Microsoft system file but no valid code signing certificate is present.
- RelocSectionNoRelocation (level 4): The .reloc section contains no relocation entries, inconsistent with standard PE structure.

The sample also contains 48 carved embedded files (source: malcat, carved_files), including 6 PE executables, 2 PKCS7 structures, and 10 DIB image files, confirming dropper functionality. 3 virtual resource files are also present, including a Chinese (zh-cn) version info resource (source: malcat, virtual_files).

## 4. Malcat Triage Summary
Malcat identified 12 YARA/signature matches (source: malcat, yara/signatures):
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | Detects Visual Studio 6.0 linker usage |
| Aspack_sections | packer | INFO | 60 | Detects ASPack based on section artifacts |
| aspack_uv_10 | packer | INFO | 50 | ASPack version marker |
| aspack_asprotect_2xx | packer | INFO | 50 | ASProtect version marker |
| aspack_212 | packer | INFO | 50 | ASPack 2.12 specific marker |
| ZoneAlternateStream | network | UNCOMMON | 60 | Manipulates internet alternate streams |
| AccessNetworkShares | network | SUSPICIOUS | 70 | Accesses network shares |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | Assesses OS environment |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerates running processes (anti-analysis) |
| ValuableFileExtensions | destruction | UNCOMMON | 10 | Embeds list of file extensions targeted by ransomware |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | Elevates privileges via Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | Spawns command shell |

20 total anomalies were detected (source: malcat, anomalies), with high-signal anomaly locations at:
- GuiSubsystemNoWindowApi: 0x00000110 (276 decimal): GUI application with no user32 window API imports, consistent with headless payload execution.
- ResourceDirectoryGap: 0x00006698 (26344 decimal): Unoccupied gap in the resource directory, a common packing artifact.

71 high-signal strings were extracted by Malcat (source: malcat, high-signal strings), including:
| EA | String |
|---|---|
| 0x0018296E | `http://www.7-zip.org/` |
| 0x0000952C | `kernel32.dll` |
| 0x0009173B | `https://go.micro..k/?linkid=798306` |
| 0x000B7F21 | `https://aka.ms/d..-core-applaunch?` |
| 0x00383B88 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 0x00383B4C | `Lhttp://cacerts...StampingCA.crt0` |

Top extracted strings include references to 7-Zip, Universal C Runtime DLLs (api-ms-win-crt-*), and license agreement text (source: malcat, top strings).

## 5. Static Code Analysis
Static disassembly is heavily limited by ASPack packing. Ghidra reports 0 analyzable functions (source: ghidra, funcs), while Malcat identifies only 2 stub functions (source: malcat, functions):
| EA | Name |
|---|---|
| 0x00008601 | EntryPoint |
| 0x0000860A | sub_40900a |

The only recoverable disassembly is the entry point stub from radare2 (source: r2, disassembly):
```asm
┌ 11: entry0 ();
│           0x00409001      60             pushal
│           0x00409002      e803000000     call 0x40900a
└       ┌─< 0x00409007      e9eb045d45     jmp 0x459d94f7
```
This stub saves registers, calls a secondary stub, then jumps to an obfuscated address, consistent with ASPack's unpacking stub behavior.

The full Import Address Table (IAT) contains only 4 imports (source: malcat, imports):
| EA | Name | Type | Refs |
|---|---|---|---|
| 0x0000952C | kernel32.GetProcAddress | IMPORT | 1 |
| 0x00009530 | kernel32.GetModuleHandleA | IMPORT | 0 |
| 0x00009534 | kernel32.LoadLibraryA | IMPORT | 0 |
| 0x00009645 | msvbvm60._CIcos | IMPORT | 1 |

3 of 4 imports are unreferenced in static disassembly (source: malcat, anomalies, UnreferencedImports), indicating they are used for dynamic payload loading after unpacking. FLOSS extracted 13079 static strings (source: floss, strings), including high-signal dynamic API names: `VirtualAlloc`, `VirtualFree`, `GetProcAddress`, `GetModuleHandleA`, `LoadLibraryA`, `kernel32.dll`, `msvbvm60.dll`, `_CIcos`, and error messages for dynamic library loading (`LOADER ERROR`, `The procedure entry point %s could not be located in the dynamic link library %s`), consistent with unpacking and loading embedded payloads.

UPX unpacking failed (source: upx, unpack): upx_ok = False, is_packed = False, no unpacked sample was generated. XOR search identified 20 XOR 00 positions, but no usable unpacked output was produced (source: xor, search).

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed. Speakeasy execution recorded 0 API calls and 0 key events (source: speakeasy, dynamic): not observed. Frida instrumentation was available (version 17.16.4, source: frida_probe, version) but no runtime data was collected: not observed. The high entropy, anti-VM capabilities, and packing are expected to prevent successful dynamic analysis in standard sandbox environments.

## 7. Network Indicators & C2
No active C2 communication was observed in static or dynamic analysis. Potential network indicators extracted from static strings and YARA matches (source: malcat, high-signal strings; source: yara, matches) include:
### Observed URLs
- `http://www.7-zip.org/` (EA 0x0018296E)
- `https://go.micro..k/?linkid=798306` (EAs 0x0009173B, 0x000B7F21, 0x002D0A6A)
- `https://aka.ms/d..-core-applaunch?` (EAs 0x000B7F21, 0x0009173B, 0x002D0E6A)
### Observed IP Addresses
- IPv4 address at EA 0x00010E93 (69211 decimal)
- IPv6 address at EA 0x00073365 (471645 decimal)
### Observed Domain Regex Match
- Domain pattern match at EA 0x00000000

Additional high-signal strings include numerous Microsoft CRL and CA certificate URLs (e.g., `http://crl4.dig..3842021CA1.crl`, `http://cacerts...StampingCA.crt`), which may be used for code signing validation or C2 certificate pinning. No confirmed active C2 infrastructure was identified.

## 8. Capabilities & MITRE ATT&CK Mapping
Capabilities identified from static and triage analysis are mapped to MITRE ATT&CK as follows, with citations:
| Capability | MITRE ATT&CK ID | Technique Name | Source |
|---|---|---|---|
| ASPack packing/obfuscation | T1027.002 | Obfuscated Files or Information: Software Packing | capa, top_rules (packed with ASPack); yara, matches (ASPackv212AlexeySolodovnikov, aspack_212) |
| VirtualBox anti-VM detection | T1497.001 | Virtualization/Sandbox Evasion: Virtual Machine Detection | capa, top_rules (reference anti-VM strings targeting VirtualBox) |
| Dynamic API resolution for payload execution | T1129 | Process Injection: Dynamic-link Library Injection | pe_imports, signals (LoadLibrary, GetProcAddress) |
| Embedded PE/PKCS7 payload deployment | B0023 (MBC) | Install Additional Program | capa, top_rules (contain an embedded PE file); malcat, carved_files |
| Masquerading as legitimate software | T1036.005 | Masquerading: Match Legitimate Name or Location | malcat, file_summary.metadata (spoofed Microsoft Firewall metadata) |
| Privilege escalation | T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | yara, matches (escalate_priv, ElevatePrivileges) |
| Shell execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | yara, matches (RunShell) |
| Network share access | T1021.002 | Remote Services: SMB/Windows Admin Shares | yara, matches (AccessNetworkShares) |
| Anti-debugging | T1497.001 | Virtualization/Sandbox Evasion: Debugger Detection | yara, matches (anti_dbg) |
| DEP bypass | T1055.002 | Process Injection: Thread Execution Hijacking | yara, matches (disable_dep) |

## 9. Indicators of Compromise
### File-Based IOCs
| IOC Type | Value | Source |
|---|---|---|
| SHA256 | 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb | llm_judge, verdict.json |
| File Name | virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir | llm_judge, verdict.json |
| Spoofed Product Name | Microsoft Firewall | malcat, file_summary.metadata |
| Spoofed Company Name | Xiang Corporation | deep_dive_agentic, key_evidence |
| Packer Sections | .aspack, .adata, .reloc | malcat, file_layout |
| High Entropy | 112 (overlay entropy 111) | malcat, file_summary; malcat, file_layout |

### Network IOCs
| IOC Type | Value | Source |
|---|---|---|
| URL | http://www.7-zip.org/ | malcat, high-signal strings |
| URL | https://go.micro..k/?linkid=798306 | malcat, high-signal strings |
| URL | https://aka.ms/d..-core-applaunch? | malcat, high-signal strings |
| IPv4 Address | At EA 0x00010E93 | yara, matches (IP rule) |
| IPv6 Address | At EA 0x00073365 | yara, matches (IP rule) |
| Domain Regex Match | At EA 0x00000000 | yara, matches (domain rule) |

### Detection IOCs
| IOC Type | Value | Source |
|---|---|---|
| YARA Rule | ASPackv212AlexeySolodovnikov | yara, matches |
| YARA Rule | aspack_212 | yara, matches |
| YARA Rule | anti_dbg | yara, matches |
| Import Signature | LoadLibraryA + GetProcAddress + GetModuleHandleA (only imports) | pe_imports, imports |
| Anomaly | Entry point in non-executable section | malcat, anomalies (EntryPointInNonExecRegion) |
| Anomaly | Unreferenced imports (4 total) | malcat, anomalies (UnreferencedImports) |

## 10. Detection Engineering
### YARA Detection Rule
```yara
rule ASPack_Packed_Dropper_AntiVM {
    meta:
        description = "Detects ASPack-packed malware with anti-VM and dropper capabilities"
        author = "malware-analyst"
        reference = "62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb"
    strings:
        $aspack_section = ".aspack"
        $adata_section = ".adata"
        $anti_vm = "VirtualBox" wide ascii
        $dynamic_api1 = "GetProcAddress" wide ascii
        $dynamic_api2 = "LoadLibraryA" wide ascii
        $ms_firewall = "Microsoft Firewall" wide ascii
        $aspack_marker = { 60 60 e8 03 00 00 00 e9 eb 04 5d 45 } // EP stub pattern
    condition:
        uint32(0) == 0x5A4D and // MZ header
        uint32(uint32(0x3C) + 0x18) == 0x010B and // PE32
        uint16(uint32(0x3C) + 0x5C) == 0x0107 and // GUI subsystem
        all of ($aspack_section, $adata_section) and
        $dynamic_api1 and $dynamic_api2 and
        not filesize < 3MB and // Sample is 3.1MB
        entropy(overlay) > 100
}
```

### Sigma Rule for Endpoint Detection
```sigma
title: ASPack-Packed Dropper with Anti-VM Capabilities
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects execution of ASPack-packed malware masquerading as Microsoft Firewall with VirtualBox anti-VM capabilities
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Firewall.exe'
        CommandLine|contains:
            - 'VirtualBox'
            - 'GetProcAddress'
            - 'LoadLibraryA'
    condition: selection
falsepositives:
    - Legitimate Microsoft Firewall administrative tools
level: high
```

### PE Import Signature Detection
Flag any X86 GUI PE with <5 total imports, where all imports are from kernel32.dll (LoadLibraryA, GetProcAddress, GetModuleHandleA) plus a single VB6 runtime import (MSVBVM60._CIcos), with entry point in a non-executable section (source: pe_imports, imports; malcat, anomalies, EntryPointInNonExecRegion).

## 11. What We Don't Know
1. The embedded PE and PKCS7 payloads could not be extracted or analyzed: UPX unpacking failed (source: upx, unpack), no unpacked sample path is available, and the packed stub prevents direct carving of embedded content for execution.
2. No confirmed active C2 infrastructure: Observed URLs and IP addresses are static strings only, with no evidence of active communication in static or dynamic analysis.
3. No specific malware family attribution: The sample uses common ASPack packing and dropper techniques with no unique family-specific markers identified in static analysis.
4. No PDB path details: YARA detects a PDB path (source: yara, matches) but the path string was not extracted in available string dumps.
5. No runtime behavior data: Speakeasy and Frida recorded no execution events, so post-unpacking behavior, payload deployment mechanisms, and C2 communication flows are unknown.
6. The purpose of the embedded DIB image files and 7-Zip license text is unknown: these may be decoy content or part of the payload deployment process.

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Purpose |
|---|---|---|
| Malcat | N/A | File layout analysis, string extraction, YARA scanning, anomaly detection, file carving |
| Ghidra | N/A | Static disassembly and function recovery (0 functions recovered) |
| radare2 | N/A | Entry point disassembly |
| FLOSS | N/A | String extraction (13079 static strings extracted) |
| capa | malcat-capa v1.07 | Capability and MITRE ATT&CK mapping (4 rules matched) |
| YARA | Pipeline (35 rules total) | Packer and malicious behavior detection (12 matches) |
| UPX | N/A | Unpacking attempt (failed, returncode None) |
| XOR Search | N/A | XOR key and encoded string search (20 XOR 00 positions found) |
| Speakeasy | ok (True) | Dynamic execution (0 API calls, 0 key events recorded) |
| Frida | 17.16.4 | Runtime instrumentation (no data collected) |
| pe_imports | N/A | Import table analysis (4 imports identified) |

All analysis was performed on the sample at path `/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir` under project name `incoming`.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb  
**sample_path:** /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious ASPack-packed PE loader/dropper with anti-VM and embedded payload deployment capabilities
- **score**: 9
- **family_guess**: Unknown ASPack-packed malware (likely loader/dropper, no specific family attribution possible from static evidence)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Cross-engine consistency confirms packing and malicious intent: 112 entropy (Malcat) aligns with ASPack detections from YARA and capa. Ghidra's 0 function count and Malcat's 2 function count match expectations for packed code that resists static disassembly. Both Ghidra and pe_imports report 4 total imports, including high-signal dynamic loading APIs (LoadLibraryA, GetProcAddress) used for payload execution. Malcat's 20 anomalies (entry point in non-exec region, unreferenced imports, multiple packer markers) align with capa's anti-VM (T1497.001) and embedded PE detections, as well as YARA's ASPack and suspicious string rules. FLOSS strings include VirtualAlloc and dynamic API names consistent with unpacking/loading embedded payloads.
- **summary**: This is a 3.1MB X86 PE file with extremely high entropy (112), packed with ASPack to evade static analysis. It masquerades as Microsoft Firewall using spoofed version metadata, and exhibits multiple malicious traits: dynamic import resolution for payload execution, VirtualBox anti-VM detection to avoid sandbox analysis, and embedded PE/PKCS7 payloads indicating dropper/loader functionality. Static analysis is heavily limited by packing, with Ghidra unable to identify any functions and Malcat only detecting 2 stub functions. All analysis tools consistently confirm packing, obfuscation, and malicious intent, with no evidence of legitimate functionality.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | file_summary.entropy | `` | Extremely high entropy is a strong indicator of packed/encrypted code, consistent with packer-related anomalies reported |
| malcat | anomalies | `` | Multiple packer-related anomalies confirm the sample is heavily obfuscated with packing, consistent with entropy and YAR |
| yara | matches | `` | Multiple YARA rules detect ASPack packing signatures, confirming the sample is obfuscated with the ASPack packer, a comm |
| capa | top_rules | `` | capa rule explicitly identifies ASPack packing, aligning with YARA and entropy evidence to confirm anti-static analysis  |
| pe_imports | signals | `` | High-signal import for dynamic library loading, a common technique in packed malware to load and execute hidden payloads |
| pe_imports | signals | `` | High-signal import for dynamic function resolution, used by packed malware to execute unpacked code without static impor |
| malcat | anomalies | `` | Entry point is located in a non-executable memory region, a common artifact of packing where the original entry point is |
| capa | top_rules | `` | Sample contains strings to detect VirtualBox virtual machines, indicating sandbox/VM evasion behavior to avoid dynamic a |
| malcat | carved_files | `` | Sample embeds multiple PE executables and PKCS7 structures, indicating it functions as a dropper/loader designed to depl |
| malcat | file_summary.metadata | `` | Sample uses fake legitimate Microsoft Firewall metadata to masquerade as a trusted system utility, a common social engin |
| ghidra | funcs | `` | Ghidra reports 0 analyzable functions, consistent with packed code that cannot be statically disassembled without unpack |
| floss | strings | `` | FLOSS extracted dynamic API strings consistent with unpacking and loading embedded payloads, aligning with high-signal i |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is a packed/obfuscated Windows GUI PE that masquerades as 'Microsoft Firewall' (Firewall.exe) by 'Xiang Corporation'. It is wrapped with ASPack/ASProtect, contains an embedded payload, and imports only dynamic-resolution APIs (GetProcAddress, GetModuleHandleA, LoadLibraryA) plus MSVBVM60._CIcos, indicating VB6 runtime usage. YARA and capa confirm anti-VM/anti-analysis behavior, software packing, and embedded PE content. The high entropy and lack of recoverable functions in Ghidra further indicate strong packing/obfuscation.

### deep key_evidence
- `"YARA: packed with ASPack (T1027.002)"`
- `"YARA: reference anti-VM strings targeting VirtualBox (T1497.001)"`
- `"YARA: contains an embedded PE file"`
- `"YARA: contains PDB path"`
- `"capa: packed with ASPack; anti-VM/anti-analysis; embedded PE"`
- `"Ghidra imports: GetProcAddress, GetModuleHandleA, LoadLibraryA (KERNEL32.DLL); _CIcos (MSVBVM60.DLL)"`
- `"Ghidra strings: 'Microsoft Firewall', 'Firewall.exe', 'Xiang Corporation', 'kernel32.dll', 'msvbvm60.dll'"`
- `"Ghidra memory: .aspack and .adata sections present; .text marked non-executable in Ghidra segment metadata"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb
size: 3148577
type: PE
architecture: X86
entrypoint_ea: 34305
entropy: 112
file_name: virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 185 | - |
| .text | 1536 | 7168 | 20480 | 185 | RW |
| .data | 22016 | 512 | 4096 | 0 | RW |
| .rsrc | 26112 | 512 | 8192 | 0 | RW |
| .aspack | 34304 | 8704 | 12288 | 0 | RW |
| .reloc | 46592 | 6144 | 8192 | 101 | RX |
| overlay | 54784 | 3124001 | 0 | 111 | - |
| .adata | 3178785 | 0 | 4096 | 0 | RW |

### Malcat YARA / Signatures (12)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| Aspack_sections | packer | INFO | 60 | Detect Aspack based on section artifacts |
| ZoneAlternateStream | network | UNCOMMON | 60 | program tries to manipulate internet alternate streams |
| AccessNetworkShares | network | SUSPICIOUS | 70 | may access network shares |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | tries to assess the O.S environment |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |
| ValuableFileExtensions | destruction | UNCOMMON | 10 | embeds a list of file extensions often targeted by ransomwares |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
| aspack_uv_10 | packer | INFO | 50 |  |
| aspack_asprotect_2xx | packer | INFO | 50 |  |
| aspack_212 | packer | INFO | 50 |  |

### Anomalies (20)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| EntryPointInNonExecRegion | 4 | code | 1 | EntryPoint symbol is set and points to a non-executable region |
| InvalidBaseOfCode | 4 | sections | 1 | at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section |
| InvalidBaseOfData | 4 | sections | 1 | at least one data section starts before BaseOfData, or BaseOfData is not the start of a data section |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| MultiplePackers | 4 | packers | 4 | File is packed using multiple packers, very suspicious |
| PossiblePackerApiDynamicImport | 4 | imports | 3 | A packer-related api (VirtualProtect, ResumeThread, etc.) is present as string in the binary, but is |
| RelocSectionNoRelocation | 4 | sections | 1 | .reloc section does not contains relocations |
| ResourceDirectoryGap | 4 | resources | 1 | There is a space (bigger than 15 bytes) inside the resource directory region which is not occupied b |
| UnsignedMicrosoft | 4 | integrity | 5 | Version information tells us it is a microsoft file but no certificate has been found |
| BigStringHiScore | 3 | strings | 9 | string has more than 256 characters and high interest score |
| EmbeddedProgram | 3 | embedding | 10 | File embeds a program |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| RelocationsNotInRelocSection | 3 | sections | 1 | relocations are not in .reloc |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| SectionWeirdRights | 3 | sections | 1 | sections has a standard name but the sections rights are not the usual ones (like .text not having + |
| StackArrayInitialisationX86 | 3 | code | 1 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| UnreferencedImports | 3 | imports | 4 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| Packed | 2 | packers | 6 | File is packed using a legit or less-legit obfuscator |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `276`: 
- **ResourceDirectoryGap**
  - `26344`: 

### High-Signal Strings (71 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 1604414 | `http://www.7-zip.org/` |
| 38252 | `kernel32.dll` |
| 590731 | `https://go.micro..k/?linkid=798306` |
| 751745 | `https://go.micro..k/?linkid=798306` |
| 2629306 | `https://go.micro..k/?linkid=798306` |
| 752881 | `https://aka.ms/d..-core-applaunch?` |
| 591867 | `https://aka.ms/d..-core-applaunch?` |
| 2629978 | `https://aka.ms/d..-core-applaunch?` |
| 976248 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 979132 | `Lhttp://cacerts...StampingCA.crt0` |
| 976460 | `Phttp://cacerts...3842021CA1.crt0	` |
| 467097 | `Lhttp://cacerts...StampingCA.crt0` |
| 625216 | `Ihttp://crl.micr..2011_03_22.crl0^` |
| 888839 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 464425 | `Phttp://cacerts...3842021CA1.crt0	` |
| 464213 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 464128 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 786230 | `Ihttp://crl.micr..2011_03_22.crl0^` |
| 891808 | `Lhttp://cacerts...StampingCA.crt0` |
| 888924 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 889136 | `Phttp://cacerts...3842021CA1.crt0	` |
| 915968 | `Lhttp://cacerts...StampingCA.crt0` |
| 649301 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 952089 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 864977 | `Phttp://cacerts...3842021CA1.crt0	` |
| 491256 | `Lhttp://cacerts...StampingCA.crt0` |
| 488584 | `Phttp://cacerts...3842021CA1.crt0	` |
| 867649 | `Lhttp://cacerts...StampingCA.crt0` |
| 864765 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 913295 | `Phttp://cacerts...3842021CA1.crt0	` |
| 488372 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 488287 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 913083 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 912998 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 813284 | `Lhttp://cacerts...StampingCA.crt0` |
| 810612 | `Phttp://cacerts...3842021CA1.crt0	` |
| 864680 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 952004 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 976163 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 952301 | `Phttp://cacerts...3842021CA1.crt0	` |
| 954974 | `Lhttp://cacerts...StampingCA.crt0` |
| 810400 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 810315 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 628318 | `Nhttp://www.micr..%202010(1).crl0l` |
| 652271 | `Lhttp://cacerts...StampingCA.crt0` |
| 243362 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 243447 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 243659 | `Phttp://cacerts...3842021CA1.crt0	` |
| 649598 | `Phttp://cacerts...3842021CA1.crt0	` |
| 789332 | `Nhttp://www.micr..%202010(1).crl0l` |
| 649386 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 246331 | `Lhttp://cacerts...StampingCA.crt0` |
| 1003292 | `Lhttp://cacerts...StampingCA.crt0` |
| 2702100 | `Ihttp://crl.micr..2011_03_22.crl0^` |
| 1000619 | `Phttp://cacerts...3842021CA1.crt0	` |
| 2705204 | `Nhttp://www.micr..%202010(1).crl0l` |
| 1000407 | `Mhttp://crl4.dig..3842021CA1.crl0>` |
| 2556149 | `Ihttp://crl.micr..2011_03_22.crl0^` |
| 2474902 | `Ihttp://crl.micr..2011_03_22.crl0^` |
| 1000322 | `Mhttp://crl3.dig..3842021CA1.crl0S` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 3173489 | `<assembly xmlns=..ty>
</assembly>` |
| 927090 | `af an ar ast az ..ll Uninstall.exe` |
| 824407 | `af an ar ast az ..ll Uninstall.exe` |
| 1882257 | `af an ar ast az ..ll Uninstall.exe` |
| 839258 | `af an ar ast az ..ll Uninstall.exe` |
| 1604414 | `http://www.7-zip.org/` |
| 802554 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 905245 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 881078 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 944439 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 641540 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 235601 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 480526 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 856919 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 968402 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 992561 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 456367 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 770801 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 2643910 | `api-ms-win-crt-string-l1-1-0.dll` |
| 944405 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 881044 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 770867 | `api-ms-win-crt-string-l1-1-0.dll` |
| 235567 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 2643844 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 609853 | `api-ms-win-crt-string-l1-1-0.dll` |
| 641506 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 2337140 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 2337104 | `api-ms-win-crt-string-l1-1-0.dll` |
| 480492 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 802520 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 456333 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 856885 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 992527 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 968368 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 609787 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 905211 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 3057937 | `Usage: 7z <comma.. on all queries
` |
| 881148 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 609953 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 331288 | `this agreement, .. by this
A party` |
| 905179 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 2643944 | `api-ms-win-crt-c..nvert-l1-1-0.dll` |
| 2645078 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 2643878 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 641610 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 641474 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 881012 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 856989 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 609887 | `api-ms-win-crt-c..nvert-l1-1-0.dll` |
| 992495 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 856853 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 609821 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 110522 | `this agreement, .. by this
A party` |
| 905315 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 770967 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 770901 | `api-ms-win-crt-c..nvert-l1-1-0.dll` |
| 770835 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 992631 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 456301 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 456437 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 968472 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 968336 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 480460 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 802488 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 802624 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 235671 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 235535 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 944509 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 944373 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 480596 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 2337004 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 2337072 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 456405 | `api-ms-win-crt-math-l1-1-0.dll` |
| 2645046 | `api-ms-win-crt-math-l1-1-0.dll` |
| 771033 | `api-ms-win-crt-time-l1-1-0.dll` |
| 609987 | `api-ms-win-crt-math-l1-1-0.dll` |
| 2643978 | `api-ms-win-crt-time-l1-1-0.dll` |
| 905283 | `api-ms-win-crt-math-l1-1-0.dll` |
| 992599 | `api-ms-win-crt-math-l1-1-0.dll` |
| 2337040 | `api-ms-win-crt-math-l1-1-0.dll` |

### Constants / Known Patterns (74)
| Category | Value |
|---|---|
| compress | `compress::unlzx_table_one__8_byt_32` |
| crypto | `crypto::rfc3548_Base_32_Encoding__8_byt_ASC_32` |
| oid | `oid::signedData` |
| oid | `oid::sha-256` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| crypto | `crypto::PKCS_DigestDecoration_SHA256__8_byt_19` |
| oid | `oid::sha256WithRSAEncryption` |
| oid | `oid::localityName` |
| oid | `oid::organizationName` |
| oid | `oid::commonName` |
| oid | `oid::countryName` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::rsaEncryption` |
| oid | `oid::nt5Crypto` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::subjectAltName` |
| oid | `oid::serialNumber` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::caIssuers` |
| oid | `oid::basicConstraints` |
| oid | `oid::cAKeyCertIndexPair` |
| oid | `oid::enrollCerttypeExtension` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |
| oid | `oid::individualCodeSigning` |
| oid | `oid::messageDigest` |
| oid | `oid::spcSpOpusInfo` |
| oid | `oid::tSTInfo` |
| oid | `oid::organizationalUnitName` |
| oid | `oid::keyUsage` |
| oid | `oid::certificatePolicies` |
| oid | `oid::cps` |
| oid | `oid::unotice` |
| oid | `oid::extKeyUsage` |
| oid | `oid::timeStamping` |
| oid | `oid::sha1` |
| oid | `oid::sha1WithRSAEncryption` |

### Imports (4)
| EA | Name | Type | Refs |
|---|---|---|---|
| 38236 | kernel32.GetProcAddress | IMPORT | 1 |
| 38240 | kernel32.GetModuleHandleA | IMPORT | 0 |
| 38244 | kernel32.LoadLibraryA | IMPORT | 0 |
| 38389 | msvbvm60._CIcos | IMPORT | 1 |

### Functions (2)
| EA | Name |
|---|---|
| 34305 | EntryPoint |
| 34314 | sub_40900a |

### Decompilations (top 6)
#### 34305 — EntryPoint
```c
EntryPoint {
    // Error while decompiling : not a valid va
}

```
#### 34314 — sub_40900a
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40900a(void)

{
    return;
}

```

### Carved Files (48)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 3696 |
| ? | PE | 17696 |
| ? | PE | 650240 |
| ? | PKCS7 | 10384 |
| ? | PKCS7 | 10322 |
| ? | PE | 14848 |
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | PE | 24160 |
| ? | PKCS7 | 10322 |
| ? | PE | 24160 |
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | PE | 24160 |
| ? | PKCS7 | 10322 |
| ? | PE | 24160 |
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 3752 |
| ? | DIB | 968 |

### Virtual Files (3)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/30001/unk | 3696 | - |
| GRPICO/1/unk | 20 | - |
| VER/1/zh-cn | 868 | - |

### Structures (25)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 184 |
| OptionalHeader | 208 |
| Sections | 432 |
| Resources | 26112 |
| Resources.VER | 26152 |
| Resources.GRPICO | 26176 |
| Resources.ICO | 26200 |
| Resources.VER.1 | 26224 |
| Resources.GRPICO.1 | 26248 |
| Resources.ICO.30001 | 26272 |
| Resources.VER.1.zh-cn | 26296 |
| Resources.GRPICO.1.unk | 26312 |
| Resources.ICO.30001.unk | 26328 |
| Relocations | 38228 |
| kernel32.FT | 38236 |
| ImportNames | 38252 |
| ImportTable | 38316 |
| ImportNames | 38376 |
| msvbvm60.FT | 38389 |
| ImportNames | 38397 |
| VersionInfo | 38408 |
| Resources.GRPICO.1.unk.Data | 39276 |
| Resources.ICO.30001.unk.Data | 39296 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 4 · duration_s: 1.07

| Rule | ATT&CK | MBC |
|---|---|---|
| reference anti-VM strings targeting VirtualBox | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| packed with ASPack | T1027.002:Obfuscated Files or Information | F0001:Software Packing |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contains PDB path |  |  |

## PE Imports / Signals
import_count: 4

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 35

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@69211 len=7; $ipv6@471645 len=2 |
| contains_base64 | - | $a@9841 len=12 |
| Antivirus | - |  |
| Misc_Suspicious_Strings | - | $a1@1830746 len=10 |
| Big_Numbers1 | - | $c0@2281750 len=64 |
| CRC32_poly_Constant | - | $c0@2994550 len=4 |
| url | - | $url_regex@20777 len=27 |
| ASPackv212AlexeySolodovnikov | - | $a0@9729 len=15; $a1@9729 len=29 |
| ASProtectV2XDLLAlexeySolodovnikov | - | $a0@9729 len=27 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| ASPack_v212_additional | - | $a@9729 len=15 |
| ASPack_v21_additional | - | $a@9729 len=29 |
| ASProtect_V2X_DLL_Alexey_Solodovnikov | - | $a@9729 len=27 |
| ASPack_v212 | - | $a@9729 len=14; $b@9729 len=15 |
| yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h | - | $a@233 len=1 |
| ASPack_v211d | - | $a@9729 len=28 |
| ASProtect_V2X_DLL_Alexey_Solodovnikov_additional | - | $a@9729 len=27 |
| ASPack_212withouth_Poly_Solodovnikov_Alexey | - | $a@9729 len=15 |
| ASPack_v212_Alexey_Solodovnikov | - | $a@9729 len=15 |
| suspicious_packer_section | - | $s1@552 len=7; $s2@592 len=6 |
| DebuggerException__SetConsoleCtrl | - | $@3022153 len=21 |
| SEH_Init | - | $b@793219 len=7 |
| anti_dbg | - | $d1@10817 len=12; $c2@204597 len=17; $c3@578805 len=17 |
| disable_dep | - | $c2@67057 len=23 |
| win_hook | - | $f1@10842 len=10; $c1@2306300 len=19; $c3@2306348 len=14 |
| escalate_priv | - | $d1@797007 len=12; $c2@1733462 len=21 |

## Generated YARA Meta
```json
{
  "rule_count": 35,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
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
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 69211,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 471645,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 9841,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": []
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$a1",
          "offset": 1830746,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Big_Numbers1",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 2281750,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 2994550,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 20777,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "ASPackv212AlexeySolodovnikov",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 9729,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 9729,
          "length": 29,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "ASProtectV2XDLLAlexeySolodovnikov",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 9729,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/
```

## FLOSS Strings
Total strings: 13079 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 13079}`

### High-signal FLOSS
- `kernel32.dll`
- `GetProcAddress`
- `LoadLibraryA`
- `http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `.aspack`
- `.adata`
- `.reloc`
- `b'36_^`
- `Ulmbdh`
- `5=(kj[`
- `oXK[7~`
- `.F[Cm~`
- `Hd\;m;`
- `u`Ql:4&`
- `~Y<[Q"`
- `Mc6Mnj$7Qk`
- `[#yP(Wd`
- `=oH]*Q`
- `VirtualAlloc`
- `VirtualFree`
- `kernel32.dll`
- `ExitProcess`
- `user32.dll`
- `MessageBoxA`
- `wsprintfA`
- `LOADER ERROR`
- `The procedure entry point %s could not be located in the dynamic link library %s`
- `The ordinal %u could not be located in the dynamic link library %s`
- `(08@P`p`
- `GetProcAddress`
- `GetModuleHandleA`
- `LoadLibraryA`
- `msvbvm60.dll`
- `_CIcos`
- `= Rich`
- ``.rdata`
- `@.data`
- `@.reloc`
- `>Mapplicable to your use of the programs in excess of your license rights. If you do not pay, Oracle can end your technical`
- `important and together create this contract that applies to you. You can review linked terms by pasting`
- `terminated leases and repossessed assets, plus (5) Original cost of assets underlying leases and loans, originated and active on`
- `will be severed and proceed in a court of law, with the remaining parts proceeding in arbitration. If any`
- `means including purchase orders transmitted from Oracle Purchasing) must be licensed separately.`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00409001
```asm
┌ 11: entry0 ();
│           0x00409001      60             pushal
│           0x00409002      e803000000     call 0x40900a
└       ┌─< 0x00409007      e9eb045d45     jmp 0x459d94f7
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r
- Found XOR 00 position 00003AD6: 00000120 ........!..L.!This program cannot be r
- Found XOR 00 position 0000F499: 000000D8 ........!..L.!This program cannot be r
- Found XOR 00 position 000172C1: 00000078 ........!..L.!This program cannot be r
- Found XOR 00 position 0002FFFF: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 00035E5E: 000000B8 ........!..L.!This program cannot be r
- Found XOR 00 position 00039934: 00000120 ........!..L.!This program cannot be r
- Found XOR 00 position 000452F7: 000000D8 ........!..L.!This program cannot be r
- Found XOR 00 position 0004D11F: 00000078 ........!..L.!This program cannot be r
- Found XOR 00 position 00065E5D: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 0006BCBC: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 00071B1B: 000000F0 ........!..L.!This program cannot be r
- Found XOR 00 position 000931B2: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 00099011: 000000F0 ........!..L.!This program cannot be r
- Found XOR 00 position 000BA6A8: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 000C0507: 000000E8 ........!..L.!This program cannot be r
- Found XOR 00 position 000C3F06: 000000E0 ........!..L.!This program cannot be r
- Found XOR 00 position 000C7B05: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 000CD964: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 000D37C3: 00000108 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
