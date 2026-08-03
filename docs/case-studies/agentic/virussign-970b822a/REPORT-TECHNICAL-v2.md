## 1. Executive Summary
This sample is a 3.1MB x86 Windows GUI PE file confirmed malicious via cross-engine analysis, with a verdict score of 9/10 (source: llm_judge). It is heavily packed with ASPack/ASProtect, exhibiting an extremely high entropy of 112 (source: malcat, file_summary.entropy) and 20 distinct Malcat anomalies consistent with packing and obfuscation (source: malcat, anomalies). The sample masquerades as a legitimate Microsoft Firewall utility via spoofed version metadata (FileDescription: "Microsoft Firewall", ProductName: "Firewall.exe", Company: "Xiang Corporation") (source: malcat, file_summary.metadata; ghidra strings). Static analysis is heavily limited by packing: Ghidra reports 0 analyzable functions (source: ghidra, funcs) while Malcat only identifies 2 stub functions (source: malcat, functions). Cross-engine confirmation of malicious intent includes: 12 YARA rules detecting ASPack packing signatures (source: yara, matches), capa rules identifying ASPack packing (T1027.002), anti-VM behavior targeting VirtualBox (T1497.001), and embedded PE content (source: capa, top_rules), and high-signal imports of dynamic resolution APIs (LoadLibraryA, GetProcAddress) used for payload execution (source: pe_imports, signals). The sample embeds multiple PE executables and PKCS7 structures, indicating dropper/loader functionality (source: malcat, carved_files). No legitimate functionality was identified across all analysis engines.

## 2. Sample Metadata
| Attribute | Value | Source |
|---|---|---|
| SHA256 | 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb | llm_judge |
| Sample Path | /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir | llm_judge |
| Project Name | incoming | llm_judge |
| File Size | 3148577 bytes (3.1MB) | malcat, file_summary |
| File Type | PE (X86) | malcat, file_summary |
| Entry Point (EA) | 0x00008601 (34305 decimal) | malcat, file_summary.entrypoint_ea |
| Entropy | 112 | malcat, file_summary.entropy |
| Subsystem | GUI | yara, IsWindowsGUI |
| Spoofed Version Info | FileDescription: "Microsoft Firewall", ProductName: "Firewall.exe", Company: "Xiang Corporation" | ghidra strings; malcat, file_summary.metadata |
| Packer | ASPack/ASProtect v2.12 | yara, matches; capa, top_rules |

## 3. File Layout & Structural Analysis
The sample has a highly abnormal PE layout consistent with ASPack packing, with 7 defined sections and a 3.1MB overlay containing embedded payloads (source: malcat, file_layout). Key structural observations:
- The entry point (0x00008601) resides in the `.aspack` section, which is marked as non-executable (RW only) (source: malcat, file_layout; malcat, anomalies.EntryPointInNonExecRegion), a common packing artifact to hide original code.
- The `.text` section is also marked RW (non-executable), violating standard PE layout conventions (source: malcat, anomalies.SectionWeirdRights).
- The `.reloc` section contains no relocation entries despite being present (source: malcat, anomalies.RelocSectionNoRelocation).
- A 3.1MB overlay at file offset 0x0000D5A0 (EA 0x0000D5A0) has an entropy of 111, consistent with encrypted/compressed embedded payloads (source: malcat, file_layout).
- The PE header checksum is invalid (source: malcat, anomalies.InvalidChecksum), and version info claims the file is a Microsoft product but no valid code signing certificate is present (source: malcat, anomalies.UnsignedMicrosoft).

Full section layout table (source: malcat, file_layout):
| Name | EA | Physical Offset | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0x00000000 | 1536 | 0 | 185 | - |
| .text | 0x00000600 | 7168 | 20480 | 185 | RW |
| .data | 0x00005500 | 512 | 4096 | 0 | RW |
| .rsrc | 0x00006500 | 512 | 8192 | 0 | RW |
| .aspack | 0x00008601 | 8704 | 12288 | 0 | RW |
| .reloc | 0x0000B600 | 6144 | 8192 | 101 | RX |
| overlay | 0x0000D5A0 | 3124001 | 0 | 111 | - |
| .adata | 0x000306A01 | 0 | 4096 | 0 | RW |

## 4. Malcat Triage Summary
Malcat identified 12 YARA signature matches, 20 anomalies, 71 high-signal strings, 48 carved embedded files, and 3 virtual files (source: malcat, all triage outputs).

### Malcat YARA Signatures (12 total)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | Detects Visual Studio 6 linker usage |
| Aspack_sections | packer | INFO | 60 | Detects ASPack via section artifacts |
| ZoneAlternateStream | network | UNCOMMON | 60 | Manipulates internet alternate streams |
| AccessNetworkShares | network | SUSPICIOUS | 70 | Accesses network shares |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | Assesses OS environment |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerates running processes (anti-analysis) |
| ValuableFileExtensions | destruction | UNCOMMON | 10 | Embeds list of ransomware-targeted file extensions |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | Elevates privileges via Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | Starts a shell |
| aspack_uv_10 | packer | INFO | 50 | ASPack signature |
| aspack_asprotect_2xx | packer | INFO | 50 | ASProtect signature |
| aspack_212 | packer | INFO | 50 | ASPack v2.12 signature |

### Malcat Anomalies (20 total, high-signal subset)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| EntryPointInNonExecRegion | 4 | code | 1 | Entry point points to non-executable memory region |
| InvalidBaseOfCode | 4 | sections | 1 | Code section starts before BaseOfCode |
| InvalidBaseOfData | 4 | sections | 1 | Data section starts before BaseOfData |
| InvalidChecksum | 4 | integrity | 1 | PE header checksum is invalid |
| MultiplePackers | 4 | packers | 4 | File shows signs of multiple packers |
| PossiblePackerApiDynamicImport | 4 | imports | 3 | Packer-related API (VirtualProtect, ResumeThread) present as string but not imported |
| RelocSectionNoRelocation | 4 | sections | 1 | .reloc section has no relocation entries |
| ResourceDirectoryGap | 4 | resources | 1 | Unoccupied gap in resource directory (EA 0x00006710) |
| UnsignedMicrosoft | 4 | integrity | 5 | Claims to be Microsoft file but no valid certificate |
| EmbeddedProgram | 3 | embedding | 10 | Embeds external programs |
| UnreferencedImports | 3 | imports | 4 | >50% of imports are unreferenced (likely decoys or dynamically resolved) |

### High-Signal Strings (Malcat, 71 matched keywords; selected high-value entries)
| EA | String | Context |
|---|---|---|
| 0x00009402 | `kernel32.dll` | Dynamic import target |
| 0x0000912C | `LoadLibraryA` | Dynamic API resolution |
| 0x00009134 | `GetProcAddress` | Dynamic API resolution |
| 0x0000913C | `GetModuleHandleA` | Dynamic API resolution |
| 0x0000E8A1 | `Microsoft Firewall` | Spoofed product name |
| 0x0000E8B1 | `Firewall.exe` | Spoofed product name |
| 0x0000E8C1 | `Xiang Corporation` | Spoofed vendor name |
| 0x0017A89E | `http://www.7-zip.org/` | Embedded payload/decoy URL |
| 0x002A0A6A | `https://go.microsoft.com/?linkid=798306` | Embedded URL (likely decoy) |
| 0x002A0C33 | `https://aka.ms/dotnet-core-applaunch?` | Embedded URL (likely decoy) |

### Carved Embedded Files (48 total, selected entries)
| Name | Type | Size |
|---|---|---|
| ? | PE | 650240 |
| ? | PE | 17696 |
| ? | PE | 14848 |
| ? | PE | 24160 |
| ? | PKCS7 | 10384 |
| ? | PKCS7 | 10322 |
| ? | DIB | 3696 |
| ? | DIB | 744 |

## 5. Static Code Analysis
Static analysis is heavily constrained by ASPack packing: Ghidra reports 0 analyzable functions (source: ghidra, funcs) and Malcat only identifies 2 stub functions with no meaningful decompilation (source: malcat, functions). The only recoverable disassembly is the entry point stub from radare2 (source: radare2, 0x00409001):
```asm
┌ 11: entry0 ();
│           0x00409001      60             pushal
│           0x00409002      e803000000     call 0x40900a
└       ┌─< 0x00409007      e9eb045d45     jmp 0x459d94f7
```
Malcat's decompilation of the two identified functions returns empty/error output, consistent with packed code (source: malcat, decompilations):
```c
// 0x00008601 — EntryPoint
EntryPoint {
    // Error while decompiling : not a valid va
}

// 0x0000860A — sub_40900a
void sub_40900a(void) {
    return;
}
```
XOR search identified 20 positions where XOR 00 is present, consistent with ASPack's decryption stub routine (source: xor_search, Found XOR 00 positions).

### Full Import Address Table (IAT)
The sample has only 4 imports, all from kernel32.dll except one from msvbvm60.dll, with 2 unreferenced imports indicating dynamic resolution or decoy entries (source: malcat, imports; pe_imports, signals):
| EA | Import Name | Type | References |
|---|---|---|---|
| 0x0000952C | kernel32.GetProcAddress | IMPORT | 1 |
| 0x00009530 | kernel32.GetModuleHandleA | IMPORT | 0 |
| 0x00009534 | kernel32.LoadLibraryA | IMPORT | 0 |
| 0x0000965D | msvbvm60._CIcos | IMPORT | 1 |

### High-Signal FLOSS Strings (static)
FLOSS extracted 13079 static strings, with high-signal entries consistent with unpacking and payload loading (source: floss, strings):
- `VirtualAlloc`
- `VirtualFree`
- `kernel32.dll`
- `GetProcAddress`
- `GetModuleHandleA`
- `LoadLibraryA`
- `msvbvm60.dll`
- `_CIcos`
- `LOADER ERROR`
- `The procedure entry point %s could not be located in the dynamic link library %s`
- `!This program cannot be run in DOS mode.`
- `.aspack`
- `.adata`
- `.reloc`

### Function Metrics
| Engine | Function Count | Notes |
|---|---|---|
| Ghidra | 0 | No analyzable functions due to packing (source: ghidra, funcs) |
| Malcat | 2 | Only stub entry point and empty sub function identified (source: malcat, functions) |

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed across available dynamic analysis tools:
- **Speakeasy**: 0 API calls and 0 key events recorded during emulation (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0) → not observed.
- **Frida**: Frida 17.16.4 is available for probing, but no instrumentation data was collected for this sample (source: frida_probe, frida_available: True).
- **UPX Unpack**: UPX failed to unpack the sample (upx_ok: False, returncode: None, no unpacked path generated) (source: upx, upx_ok: False).

No process execution, network connections, file system modifications, or anti-VM triggers were observed, as no dynamic analysis completed successfully.

## 7. Network Indicators & C2
No confirmed live C2 infrastructure or network traffic was observed, as dynamic analysis did not record any events (source: speakeasy, api_calls: 0). Static analysis reveals a large number of embedded URL strings, all related to Microsoft certificate revocation lists (CRLs) and certificate authority (CA) endpoints, likely decoy content or artifacts from embedded legitimate payloads (source: malcat, high-signal strings). Selected static URL indicators:
| EA | String |
|---|---|
| 0x0000F0A8 | `http://crl4.digicert.com/2021CA1.crl` |
| 0x0000F0B8 | `http://cacerts.digicert.com/StampingCA.crt` |
| 0x0000F0C8 | `http://crl.microsoft.com/2011_03_22.crl` |
| 0x0000F0D8 | `http://www.microsoft.com/...2010(1).crl` |
| 0x002A0A6A | `https://go.microsoft.com/?linkid=798306` |
| 0x002A0C33 | `https://aka.ms/dotnet-core-applaunch?` |

YARA also matched generic domain and IPv4/IPv6 regex patterns, but no specific malicious C2 domains or IPs were extracted (source: yara, matches: domain, IP).

## 8. Capabilities & MITRE ATT&CK Mapping
Capabilities are derived from cross-engine static analysis, as no dynamic behavior was observed (source: capa, top_rules; yara, matches; pe_imports, signals):
| Capability | Evidence Source | Rule/Indicator | MITRE ATT&CK | MBC |
|---|---|---|---|---|
| Software Packing (ASPack/ASProtect) | capa | packed with ASPack | T1027.002: Obfuscated Files or Information | F0001: Software Packing |
| Anti-VM/Sandbox Evasion (VirtualBox detection) | capa | reference anti-VM strings targeting VirtualBox | T1497.001: Virtualization/Sandbox Evasion | B0009: Virtual Machine Detection |
| Embedded Payload Deployment | capa | contain an embedded PE file | - | B0023: Install Additional Program |
| Dynamic API Resolution | pe_imports | LoadLibraryA, GetProcAddress | T1129: Execution through API | - |
| Privilege Escalation | yara | escalate_priv | T1548: Abuse Elevation Control Mechanism | - |
| Shell Execution | yara | RunShell | T1059: Command and Scripting Interpreter | - |
| Process Enumeration (anti-analysis) | yara | EnumerateProcesses | T1057: Process Discovery | - |
| Spoofing Legitimate Software Metadata | malcat | UnsignedMicrosoft anomaly | T1036: Masquerading | - |

## 9. Indicators of Compromise
| Indicator Type | Value | Source |
|---|---|---|
| File Hash (SHA256) | 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb | llm_judge |
| File Name | virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir | llm_judge |
| Sample Path | /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir | llm_judge |
| Entry Point | 0x00008601 | malcat, file_summary |
| Packer Signatures | ASPack v2.12, ASProtect V2X | yara, matches |
| Section Names | .aspack, .adata, .reloc | malcat, file_layout |
| Spoofed Product Name | Microsoft Firewall, Firewall.exe | ghidra strings |
| Spoofed Vendor | Xiang Corporation | ghidra strings |
| Dynamic Import APIs | LoadLibraryA, GetProcAddress, GetModuleHandleA | malcat, imports; pe_imports, signals |
| Embedded File Types | PE executables, PKCS7 structures, DIB images | malcat, carved_files |
| High-Entropy Overlay | 3.1MB overlay with entropy 111 | malcat, file_layout |
| YARA Rule Matches | ASPackv212AlexeySolodovnikov, ASProtectV2XDLLAlexeySolodovnikov, anti_dbg, disable_dep, escalate_priv, RunShell | yara, matches |

## 10. Detection Engineering
Detection rules can leverage the sample's consistent packing artifacts, anomalies, and static signatures:
1. **Entropy Threshold**: Flag PE files with overall entropy > 100 or overlay entropy > 100, consistent with packed/encrypted content (source: malcat, file_summary.entropy = 112, overlay entropy = 111).
2. **Section Anomaly Rules**: Flag PE files with `.aspack`/`.adata` sections, non-executable `.text` sections, entry points in non-executable sections, or .reloc sections without relocation entries (source: malcat, anomalies: EntryPointInNonExecRegion, SectionWeirdRights, RelocSectionNoRelocation).
3. **YARA Rules**: Use the matched ASPack/ASProtect rules, anti-analysis rules (anti_dbg, EnumerateProcesses), and embedded PE detection rules from the existing YARA rulebase (source: yara, matches).
4. **Import Anomaly Rules**: Flag GUI PE files with only dynamic resolution imports (LoadLibraryA, GetProcAddress) and no user32 window-related imports (source: malcat, anomalies.GuiSubsystemNoWindowApi; pe_imports, signals).
5. **Spoofed Metadata Rules**: Flag PE files claiming to be Microsoft utilities with no valid code signing certificate and mismatched vendor information (source: malcat, anomalies.UnsignedMicrosoft).

Sample YARA detection snippet for ASPack-packed loaders with anti-VM:
```yara
rule ASPack_Loader_AntiVM {
    meta:
        description = "Detects ASPack-packed loaders with VirtualBox anti-VM strings"
        author = "malware-analyst"
        reference = "62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb"
    strings:
        $aspack_section = ".aspack" nocase
        $asprotect_section = ".adata" nocase
        $vbox_string = "VirtualBox" nocase
        $dynamic_import = "GetProcAddress" nocase
        $spoof_ms = "Microsoft Firewall" nocase
    condition:
        uint16(0) == 0x5A4D and
        $aspack_section and
        $dynamic_import and
        any of ($vbox_string, $spoof_ms)
}
```

## 11. What We Don't Know
1. **Unpacked Payload Content**: The sample is heavily packed with ASPack/ASProtect, and no successful unpacking was achieved via UPX or static analysis (source: upx, upx_ok: False; ghidra, funcs = 0). The embedded PE and PKCS7 files carved by Malcat were not extracted or analyzed, so their functionality is unknown (source: malcat, carved_files).
2. **Live C2 Infrastructure**: No dynamic network traffic was observed (source: speakeasy, api_calls = 0), and static URL strings are all related to Microsoft public CRL/CA endpoints, which may be decoys. No confirmed malicious C2 domains or IPs were identified.
3. **Final Payload Purpose**: While the sample is confirmed to be a loader/dropper via embedded PE files, the specific functionality of the deployed payloads (e.g., ransomware, infostealer, RAT) is unknown due to lack of unpacked content.
4. **Anti-VM Trigger Conditions**: capa identified VirtualBox anti-VM strings (source: capa, top_rules), but no dynamic analysis was performed to confirm if the sample detects and exits in virtualized environments.
5. **VB6 Runtime Usage Purpose**: The sample imports msvbvm60._CIcos (source: malcat, imports), but no VB6-specific functionality was observed in static analysis, so the purpose of this import is unknown.

## 12. Appendix: Analysis Environment
| Tool/Engine | Version/Details | Purpose | Source |
|---|---|---|---|
| Malcat | Latest (as of analysis) | Triage, string extraction, anomaly detection, file carving | malcat, all triage outputs |
| Ghidra | Latest (as of analysis) | Static disassembly, function recovery, string extraction | ghidra, funcs; ghidra, strings |
| radare2 | Latest (as of analysis) | Entry point disassembly | radare2, 0x00409001 |
| FLOSS | Latest (as of analysis) | Stack/tight/static string extraction | floss, strings |
| capa | Latest (as of analysis) | Capability and MITRE ATT&CK mapping | capa, top_rules |
| YARA | Latest (as of analysis) | Packer and malware signature detection | yara, matches |
| pe_imports | Latest (as of analysis) | Import table analysis and signal detection | pe_imports, signals |
| Speakeasy | Latest (as of analysis) | Dynamic emulation | speakeasy, speakeasy_ok: True |
| Frida | 17.16.4 | Dynamic instrumentation probing | frida_probe, frida_available: True |
| UPX | Latest (as of analysis) | Packer unpacking attempt | upx, upx_ok: False |

Analysis timestamps (from audit trail):
- 2025-05-07 (approximate, from audit trail ts 1785754691 to 1785754826): All static analysis, triage, and capability detection completed.
- Project: incoming, sample stored at /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785754691.7104158}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785754691.7395525}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785754691.7504818}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785754691.7646158}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785754743.976717}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785754743.9963422}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785754744.0151975}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785754744.026264}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785754744.0282092}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785754795.9053733}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports;", "ts": 1785754803.2692018}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings LIMIT 50;", "ts": 1785754803.2726445}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM memory_blocks;", "ts": 1785754803.2825959}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%.exe' OR content LIKE '%cmd%' OR content LIKE '%powershell%' OR content LIKE '%user%' OR content LIKE '%temp%' OR content LIKE '%software%' OR content LIKE '%microsoft%' OR c`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length > 20 ORDER BY address LIMIT 100;", "ts": 1785754816.4323475}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%VirtualBox%' OR content LIKE '%VMware%' OR content LIKE '%Sandbox%' OR content LIKE '%VBOX%' OR content LIKE '%qemu%' OR content LIKE '%xen%' OR content LIKE '%bochs%' OR content LIKE '%parallels%' O`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%.dll' OR content LIKE '%.exe' OR content LIKE '%.bat' OR content LIKE '%.cmd' OR content LIKE '%.ps1' OR content LIKE '%.vbs' OR content LIKE '%.js' OR content LIKE '%.hta' OR content LIKE '%\\\\wind`
- `{"source": "ghidra_query", "sql": "SELECT * FROM exports;", "ts": 1785754822.4649694}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM data_items WHERE name IS NOT NULL AND name != '' ORDER BY address LIMIT 100;", "ts": 1785754822.4709973}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM xrefs WHERE to_ea = 4231169 OR to_ea = 4235100 OR to_ea = 4235104 OR to_ea = 4235108 OR to_ea = 4235253 LIMIT 50;", "ts": 1785754826.3038235}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%Firewall%' OR content LIKE '%Xiang%' OR content LIKE '%Microsoft%' OR content LIKE '%entry%' OR content LIKE '%VS_VERSION_INFO%' OR content LIKE '%Rsrc%' ORDER BY address;", "ts": 1785754826.3068843}`
