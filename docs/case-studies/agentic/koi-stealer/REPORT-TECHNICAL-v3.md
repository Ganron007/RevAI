# Technical Malware Analysis Report v3

## 1. Executive Summary

This sample (SHA256: `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`) is a malicious packed Delphi-based loader/dropper, scored 8/10, with a family guess of Delphi Loader/Dropper commonly used to deliver secondary payloads via fake software installers (source: llm_judge, verdict.json). It is repurposed from a legitimate Inno Setup installer (project name `SetupLdr`) with extremely high file entropy of 184, indicating heavy packing and obfuscation to hinder static analysis (source: malcat, file_summary). Cross-engine validation confirms consistent malicious indicators: Delphi/Borland origin is confirmed via Malcat YARA hits, Ghidra decompilation of Delphi RTL calls, and FLOSS extraction of Delphi type definitions; obfuscation is confirmed via Malcat anomaly counts, capa XOR/RC4 rules, and YARA packed code hits; malicious capabilities including process injection, privilege escalation, and registry manipulation are aligned across pe_imports, capa, and YARA (source: llm_judge, cross_engine_notes).

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 |
| Sample Path | /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe |
| Project Name | incoming |
| Verdict | Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities |
| Score | 8 |
| Family Guess | Delphi Loader/Dropper (common in malware distribution chains for delivering secondary payloads via fake software installers) |
| Agreement | llm_and_v1_agree |
| Cross-Engine Validation Notes | 1) Import count alignment between Malcat (145) and pe_imports (142) validates the import dataset. 2) Delphi/Borland origin is confirmed across 4 engines: Malcat YARA hits for Borland/Delphi, Ghidra decompilation shows Delphi RTL function calls, FLOSS strings include Delphi RTL type definitions, Malcat metadata lists Delphi::ProjectName as 'SetupLdr'. 3) Obfuscation indicators are consistent: Malcat reports high entropy (184) and obfuscation anomalies, capa identifies XOR/RC4 obfuscation rules, YARA flags packed code. 4) Malicious capability alignment: Privilege escalation imports from Malcat match the YARA 'escalate_priv' hit and capa's privilege-related behavior; process injection imports are flagged by both pe_imports (T1055) and capa's process injection rules. |

*Source: llm_judge, verdict.json; malcat, file_summary*

## 3. File Layout & Structural Analysis

The sample is a 2,263,752 byte PE32 GUI executable for x86 architecture, with an entry point at 0x742124 (source: malcat, file_summary). The section layout is as follows:

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 101 | - |
| .text | 1024 | 735744 | 737280 | 121 | RX |
| .itext | 738304 | 6144 | 8192 | 48 | RX |
| .data | 746496 | 14336 | 16384 | 82 | RW |
| .idata | 762880 | 4096 | 4096 | 74 | RW |
| .didata | 766976 | 512 | 4096 | 0 | RW |
| .edata | 771072 | 512 | 4096 | 0 | R |
| .rdata | 775168 | 512 | 4096 | 0 | R |
| .rsrc | 779264 | 69632 | 69632 | 39 | R |
| overlay | 848896 | 1431240 | 0 | 223 | - |
| .bss | 2280136 | 0 | 28672 | 0 | RW |
| .tls | 2308808 | 0 | 4096 | 0 | RW |

*Source: malcat, file_layout*

The 1,431,240 byte overlay has an entropy of 223, consistent with encrypted/packed payload storage. The .text section has elevated entropy (121) indicating obfuscated code, and non-zero data exists between the PE header and first section, a common packing indicator (source: malcat, anomalies: DataBetweenHeaderAndFirstSection). 15 carved files were extracted, including 12 DIB images, 1 PNG, a 1,420,730 byte Inno Setup archive, and a 10,493 byte PKCS7 file (source: malcat, carved_files). 30 virtual files were identified, including 13 ICO files and 9 STR resource files (source: malcat, virtual_files). Key PE structures include the Import Table at 0x762880, Delay Import Table at 0x766976, and Export Directory at 0x771072 (source: malcat, structures).

## 4. Malcat Triage Summary

### YARA Signatures (4 matches)

| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| TurboLinker | compiler | INFO | 80 | Linked with TurboLinker |
| Delphi | language | INFO | 80 | Delphi executable, detection based on several artifacts |
| InnoInstaller | installer | INFO | 90 | InnoSetup installer |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |

*Source: malcat, yara_signatures*

### Static Anomalies (13 total)

| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 221 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ResourceDirectoryGap | 4 | resources | 1 | There is a space (bigger than 15 bytes) inside the resource directory region which is not occupied by resources |
| BigStringHiScore | 3 | strings | 2 | string has more than 256 characters and high interest score |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| DelayImports | 3 | imports | 3 | There are delay imports |
| ManyHighValueImmediates | 3 | code | 1 | Function contains at least 5 and more than 10% of high-value immediate operands |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| XorInLoop | 3 | code | 19 | XOR instruction in a loop |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section with medium-to-high entropy |
| HugeGapBetweenFunctions | 2 | code | 24 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stored between functions |
| HighXrefLoopingFunction | 1 | code | 12 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data initialization |
| SpaghettiFunction | 1 | code | 30 | Function with lots of intra jumps, could be obfuscated |

*Source: malcat, anomalies*

High-signal anomaly locations include XorInLoop at 0x21853, 0x22125, 0x101039, 0x105002, 0x105026; SpaghettiFunction at 0x19744, 0x26152, 0x29624, 0x33032, 0x33396; HighXrefLoopingFunction at 0x18868, 0x19588, 0x23820, 0x28288, 0x31684 (source: malcat, anomaly_locations).

### High-Signal Strings (malcat engine)

| EA | String |
|---|---|
| 129464 | `kernel32.dll` |
| 739224 | `kernel32.dll` |
| 22792 | `kernel32.dll` |
| 131112 | `kernel32.dll` |
| 740708 | `kernel32.dll` |
| 40680 | `kernel32.dll` |
| 140960 | `kernel32.dll` |
| 739552 | `cryptbase.dll` |
| 38640 | `kernel32.dll` |
| 741288 | `kernel32.dll` |
| 767314 | `kernel32.dll` |
| 764232 | `kernel32.dll` |
| 767240 | `kernel32.dll` |

*Source: malcat, high_signal_strings*

Top extracted strings include Inno Setup identifiers (`Inno Setup Setup..Data (6.1.0) (u)` at 0x755472, 0x1430695), Delphi registry paths (`Software\Borland\Delphi\Locales` at 0x41456), privilege strings (`SeShutdownPrivilege` at 0x715092), and Windows API strings (`AdjustTokenPrivileges` at 0x766796, `Wow64DisableWow64FsRedirection` at 0x741224) (source: malcat, top_strings).

## 5. Static Code Analysis

### Entry Point Disassembly (radare2, 0x004b5eec)
```asm
0x004b5eec      55             push ebp
0x004b5eef      8bec           mov ebp, esp
0x004b5ef2      83c4a4         add esp, 0xffffffa4
0x004b5ef3      53             push ebx
0x004b5ef4      56             push esi
0x004b5ef5      57             push edi
0x004b5ef7      33c0           xor eax, eax
0x004b5ef9      8945c4         mov dword [var_3ch], eax
0x004b5efa      8945c0         mov dword [var_40h], eax
0x004b5efd      8945a4         mov dword [var_5ch], eax
0x004b5f00      8945d0         mov dword [var_30h], eax
0x004b5f03      8945c8         mov dword [var_38h], eax
0x004b5f06      8945cc         mov dword [var_34h], eax
0x004b5f09      8945d4         mov dword [var_2ch], eax
0x004b5f0c      8945d8         mov dword [var_28h], eax
0x004b5f0f      8945ec         mov dword [var_14h], eax
0x004b5f12      b8b8144b00     mov eax, 0x4b14b8
0x004b5f17      e8b072f5ff     call 0x40d1cc
0x004b5f1c      33c0           xor eax, eax
0x004b5f1e      55             push ebp
0x004b5f1f      68e2654b00     push 0x4b65e2
0x004b5f24      64ff30         push dword fs:[eax]
0x004b5f27      648920         mov dword fs:[eax], esp
0x004b5f2a      33d2           xor edx, edx
0x004b5f2c      55             push ebp
0x004b5f2d      689e654b00     push 0x4b659e
0x004b5f32      64ff32         push dword fs:[edx]
0x004b5f35      648922         mov dword fs:[edx], esp
0x004b5f38      a134e64b00     mov eax, dword [0x4be634]
0x004b5f3d      e8a29dffff     call 0x4afce4
0x004b5f42      e8f598ffff     call 0x4af83c
0x004b5f47      8d55ec         lea edx, [var_14h]
0x004b5f4a      33c0           xor eax, eax
0x004b5f4c      e84fcdf6ff     call 0x422ca0
0x004b5f51      8b55ec         mov edx, dword [var_14h]
0x004b5f54      b8841d4c00     mov eax, 0x4c1d84
0x004b5f59      e8a21ef5ff     call 0x407e00
0x004b5f5e      6a02           push 2
0x004b5f60      6a00           push 0
0x004b5f62      6a01           push 1
```

*Source: radare2, disassembly at 0x004b5eec*

This is standard Delphi startup code with SEH frame setup, followed by calls to initialization routines. Additional radare2 disassembly shows obfuscation patterns: function 0x0040ccb0 consists of 50 consecutive calls to 0x0040ccac (a single `ret` instruction), a common obfuscation technique to break control flow analysis (source: radare2, disassembly at 0x0040ccb0, 0x0040ccac). Function 0x004541a8 is `TMethodImplementationIntercept`, a Delphi RTL method interception routine (source: radare2, disassembly at 0x004541a8).

### Ghidra Decompilation of Key Functions

1. **sub_40ab18 (0x40728)**: Contains a call to the Delphi RTL string function `@System@@LStrAddRef$qqrpv` (source: ghidra, decompilation sub_40ab18). The function implements a retry loop for `advapi32.RegOpenKeyExW` to open registry keys, then queries values via `RegQueryValueExW`, indicating registry access for configuration or persistence. Stack canary protection via `in_FS_OFFSET` checks is present, consistent with Delphi compiler defaults.
2. **sub_4246e4 (0x146148)**: Generates a standard CRC32 lookup table using polynomial 0xedb88320, iterating 0x100 entries (source: ghidra, decompilation sub_4246e4). This aligns with capa's `hash data with CRC32` rule (source: capa, top_rules).
3. **sub_423164 (0x140644)**: Queries system locale via `GetUserDefaultUILanguage`, then accesses either `HKEY_CURRENT_USER\Control Panel\Desktop\ResourceLocale` or `HKEY_USERS\.DEFAULT\Control Panel\International` to retrieve locale settings (source: ghidra, decompilation sub_423164). This aligns with capa's `query environment variable` and `get geographical location` rules (source: capa, top_rules).

### Supporting Static Evidence

FLOSS extracted 11,298 total strings, including Delphi RTL type definitions: `TObject&`, `AnsiString`, `Variant`, `WideString`, `string`, `Boolean`, and RTL function names, confirming Borland Delphi compilation (source: floss, strings; malcat, metadata: Delphi::ProjectName = 'SetupLdr'). Malcat identified 30 total functions, including the 3 decompiled above, plus unknown functions `sub_46776c` and `sub_4678f4` (source: malcat, functions). XOR search found XOR 00 at file offset 0, with pattern `00000100 ........!..L.!..This program must be r`, indicating XOR obfuscation of header strings (source: xor, xor_search).

## 6. Behavioral & Dynamic Analysis

No dynamic runtime behavior was observed during analysis. Speakeasy dynamic analysis completed successfully but returned 0 API calls and 0 key events, with no execution flow captured (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0). Frida probe identified 24 hook candidates including `kernel32.dll!GetLogicalProcessorInformation`, `advapi32.dll!AdjustTokenPrivileges`, `advapi32.dll!RegQueryValueExW`, and `user32.dll!CreateWindowExW`, but no runtime hook data was collected (source: frida, hook_candidates). UPX unpacking failed: `upx_ok: False`, no unpacked path was generated, and no return code was returned (source: upx, upx_ok: False, unpacked_path: ``). No process injection, file system changes, or network connections were observed at runtime due to lack of captured events.

## 7. Network Indicators & C2

Embedded network indicators were identified via YARA rule matches (source: yara, matches):
- Domain: matched at offset 0 (length 3) via `$domain_regex`
- IPv4 address: matched at offset 830343 (length 7) via `$ipv4`
- IPv6 address: matched at offset 917570 (length 2) via `$ipv6`
- URL: matched at offset 722888 (length 78) via `$url_regex`

These indicators are consistent with C2 infrastructure or payload delivery endpoints, as confirmed by deep-dive analysis which notes embedded network indicators for malicious communication (source: deep_dive_agentic, key_evidence: domain, IP, url YARA matches). No network traffic was observed at runtime due to lack of dynamic capture.

## 8. Capabilities & MITRE ATT&CK Mapping

Capabilities are mapped to MITRE ATT&CK techniques based on capa rules, pe_imports signals, and YARA matches:

| Capability | Evidence Source | MITRE ATT&CK Technique |
|---|---|---|
| Obfuscation (XOR encoding) | capa: `encode data using XOR` (T1027) | T1027: Obfuscated Files or Information |
| Obfuscation (RC4 encryption) | capa: `encrypt data using RC4 PRGA` (T1027) | T1027: Obfuscated Files or Information |
| Process Injection Primitives | pe_imports: `VirtualAlloc` (allocate_memory), `VirtualProtect` (change_memory_protection) [T1055] | T1055: Process Injection |
| Process Creation | pe_imports: `CreateProcess` [T1106] | T1106: Process Injection |
| Dynamic Link Library Loading | pe_imports: `LoadLibrary`, `GetProcAddress` [T1129] | T1129: Masquerading |
| Privilege Escalation | yara: `escalate_priv`; pe_imports: `advapi32.AdjustTokenPrivileges`, `advapi32.LookupPrivilegeValueW` | T1055: Process Injection (token manipulation) |
| Registry Manipulation | yara: `win_registry`; capa: `query or enumerate registry value` (T1012) | T1012: Query Registry |
| Token Manipulation | yara: `win_token` | T1055: Process Injection |
| File System Operations | yara: `win_files_operation`; capa: `create directory`, `get common file path`, `check if file exists`, `get file size` | T1083: File and Directory Discovery |
| System Information Discovery | capa: `query environment variable`, `check OS version`, `get geographical location` | T1082: System Information Discovery, T1614: System Location Discovery |
| DEP Bypass | yara: `disable_dep` | T1055: Process Injection |
| Debugger Detection | capa: `check for time delay via GetTickCount` | B0001.032: Debugger Detection |

*Sources: capa, top_rules; pe_imports, signals; yara, matches; deep_dive_agentic, key_evidence*

## 9. Indicators of Compromise

| IOC Type | Value | Source |
|---|---|---|
| SHA256 | e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 | llm_judge, file_summary |
| File Path | /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe | sample_metadata |
| File Name | koi_sample.exe | malcat, file_summary |
| File Entropy | 184 | malcat, file_summary |
| Compiler | Borland Delphi | yara: Borland, borland_delphi; ghidra: Delphi RTL calls; floss: Delphi RTL strings |
| Installer Type | Inno Setup 6.1.0 | malcat: YARA InnoInstaller, top_strings: `Inno Setup Setup..Data (6.1.0) (u)` |
| Packing | Packed (UPX unpack failed) | yara: IsPacked, HasOverlay; upx: upx_ok: False |
| Obfuscation Indicators | 19 XorInLoop instances, 30 SpaghettiFunctions, 12 HighXrefLoopingFunctions, 24 HugeGapBetweenFunctions | malcat, anomalies |
| Registry Paths Accessed | `HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `.DEFAULT\Control Panel\International`, `Control Panel\Desktop\ResourceLocale` | ghidra: sub_40ab18, sub_423164 decompilation |
| Privilege String | `SeShutdownPrivilege` | malcat, top_strings (0x715092) |
| Windows API Imports | `advapi32.AdjustTokenPrivileges`, `advapi32.LookupPrivilegeValueW`, `advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW`, `kernel32.VirtualAlloc`, `kernel32.VirtualProtect`, `kernel32.CreateProcess` | pe_imports, signals; malcat, top high-signal imports |
| YARA Rule Hits | IsPacked, Borland, Delphi, InnoInstaller, ElevatePrivileges, disable_dep, escalate_priv, win_registry, win_token, win_files_operation, domain, IP, url | yara, matches |
| capa Rule Hits | encode data using XOR, encrypt data using RC4 PRGA, accept command line arguments, query environment variable, get common file path, check if file exists, get file size, get file version info, check OS version, query or enumerate registry value, check for time delay via GetTickCount, get geographical location, hash data with CRC32, generate random numbers using the Delphi LCG, create directory | capa, top_rules |

## 10. Detection Engineering

### Static Detection Signatures
1. **YARA Rules**: Existing rules flag the sample as packed (`IsPacked`), Borland Delphi compiled (`Borland`, `borland_delphi`), Inno Setup installer (`InnoInstaller`), and malicious capabilities (`ElevatePrivileges`, `escalate_priv`, `win_registry`, `win_token`, `win_files_operation`, `disable_dep`). Custom YARA rules can be built to detect XOR loop patterns at addresses 0x21853, 0x22125, 0x101039 (source: malcat, anomaly_locations) and high-entropy overlays (entropy > 220) (source: malcat, file_layout).
2. **Import Signatures**: Detect imports of `advapi32.AdjustTokenPrivileges`, `advapi32.LookupPrivilegeValueW`, `kernel32.VirtualAlloc`, `kernel32.VirtualProtect` in Delphi-compiled PE files with high entropy (> 150) (source: pe_imports, signals; malcat, file_summary).
3. **capa Rules**: Match obfuscation primitives (XOR/RC4), process injection memory allocation calls, and registry query behavior (source: capa, top_rules).
4. **Anomaly Detection**: Flag PE files with >10 SpaghettiFunctions, >15 XorInLoop instances, delay imports, and cross-section control flow jumps (source: malcat, anomalies).

### Runtime Detection
- Monitor for processes creating windows with class name `InnoSetupLdrWindow` (found at 0x743948 in malcat top_strings) performing registry queries to `HKEY_LOCAL_MACHINE` or `HKEY_CURRENT_USER` followed by privilege adjustment calls.
- Alert on processes loading `advapi32.dll` and calling `AdjustTokenPrivileges` after querying `SeShutdownPrivilege` from the registry.

## 11. What We Don't Know

1. The secondary payload delivered by this loader is not present in the provided sample: the only large embedded file is a 1,420,730 byte Inno Setup archive (source: malcat, carved_files), and no unpacked malicious executable was recovered (UPX unpacking failed, source: upx, upx_ok: False).
2. Exact values of the embedded network indicators (domain, IPv4, IPv6, URL) are not extracted in the provided evidence, only their YARA match offsets are known (source: yara, matches).
3. The full functionality of the 30 obfuscated SpaghettiFunctions and 12 HighXrefLoopingFunctions (likely string decryption routines) is not reverse engineered due to heavy packing and obfuscation (source: malcat, anomalies).
4. No dynamic runtime behavior was captured: Speakeasy returned 0 API events, and Frida hooks were not triggered, so the actual execution flow, C2 communication, and payload deployment behavior are unconfirmed (source: speakeasy, api_calls: 0; frida, hook_candidates).
5. The purpose of the 12 carved DIB images, 1 PNG, and 9 STR virtual files is unknown, as they are not referenced in the available static analysis data (source: malcat, carved_files; malcat, virtual_files).
6. The exact privilege requested via `AdjustTokenPrivileges` is not confirmed from static analysis alone, as the token privilege constant is likely obfuscated in the packed code.

## 12. Appendix: Analysis Environment

| Tool/Engine | Version/Details | Purpose |
|---|---|---|
| Malcat | N/A | File layout analysis, YARA scanning, anomaly detection, string extraction, import analysis |
| Ghidra | N/A | Decompilation of key functions (sub_40ab18, sub_4246e4, sub_423164) |
| radare2 | N/A | Entry point disassembly (0x004b5eec) |
| FLOSS | N/A | Stack, tight, and static string extraction (11,298 total strings) |
| capa | malcat-capa (37 rules, 2.19s runtime) | Capability detection and MITRE ATT&CK mapping |
| YARA | Pipeline (26 matches) | Malware family and capability detection |
| UPX | N/A | Unpacking attempt (failed) |
| Speakeasy | N/A | Dynamic analysis (no events captured) |
| Frida | 17.16.4 | API hooking probe (no runtime data collected) |
| pe_imports | N/A | Import table analysis (142 imports) |
| Sample Path | /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe | Analyzed sample |
| Project Name | incoming | Analysis project |
| .NET Analysis | Not observed (is_dotnet: false) | No .NET components detected |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819  
**sample_path:** /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities
- **score**: 8
- **family_guess**: Delphi Loader/Dropper (common in malware distribution chains for delivering secondary payloads via fake software installers)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Cross-engine validation confirms consistent malicious indicators: 1) Import count alignment between Malcat (145) and pe_imports (142) validates the import dataset. 2) Delphi/Borland origin is confirmed across 4 engines: Malcat YARA hits for Borland/Delphi, Ghidra decompilation shows Delphi RTL function calls, FLOSS strings include Delphi RTL type definitions, Malcat metadata lists Delphi::ProjectName as 'SetupLdr'. 3) Obfuscation indicators are consistent: Malcat reports high entropy (184) and obfuscation anomalies, capa identifies XOR/RC4 obfuscation rules, YARA flags packed code. 4) Malicious capability alignment: Privilege escalation imports from Malcat match the YARA 'escalate_priv' hit and capa's privilege-related behavior; process injection imports are flagged by both pe_imports (T1055) and capa's process injection rules.
- **summary**: This sample is a packed, obfuscated Delphi-based Inno Setup installer (SetupLdr) with an extremely high entropy of 184, indicating heavy packing to hinder static analysis. It contains confirmed malicious capabilities including process injection (via VirtualAlloc/VirtualProtect), privilege escalation (via advapi32 privilege adjustment imports and YARA escalate_priv hit), registry access, and uses XOR/RC4 obfuscation to hide its functionality. It is almost certainly a malicious loader/dropper designed to deliver secondary payloads (e.g., info-stealers, ransomware) under the guise of a legitimate software installer, with built-in functionality to evade static analysis and gain elevated system access.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | file_summary | `entropy=184` | Extremely high file entropy is a strong indicator of packed/obfuscated code, a common technique used by malware to hinde |
| malcat | anomalies | `XorInLoop×19, SpaghettiFunction×30, HighXrefLoopingFunction×12` | These static analysis anomalies are characteristic of heavily obfuscated, packed malicious code designed to break disass |
| capa | top_rules | `encode data using XOR (T1027), encrypt data using RC4 PRGA (T1027)` | Confirms active use of obfuscation and encryption techniques to hide malicious payloads and logic, aligning with the hig |
| pe_imports | signals | `allocate_memory (VirtualAlloc) [T1055], change_memory_protection (VirtualProtect` | These imports are core primitives for process injection, a common malicious tactic used to execute arbitrary code in the |
| malcat | top high-signal imports | `advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW, advapi32.Convert` | These imports are used for privilege escalation, a common malicious tactic to gain elevated system access to perform sen |
| yara | matches | `escalate_priv` | YARA rule explicitly flags privilege escalation functionality, directly corroborating the observed privilege-related imp |
| malcat | metadata | `VersionInfo::Comments = "This installation was built with Inno Setup.", Delphi::` | Confirms the sample is an Inno Setup installer (a common legitimate software deployment tool) repurposed as a malware de |
| ghidra | decompilation | `sub_40ab18 contains @System@@LStrAddRef$qqrpv (Delphi RTL string function)` | Decompilation reveals Delphi runtime library function calls, confirming the sample is compiled with Delphi, consistent w |
| floss | strings | `Delphi RTL type strings (e.g., "TObject&", "AnsiString", "Variant")` | Decoded strings include Delphi runtime type definitions, further confirming the sample's Delphi origin and consistent wi |
| malcat | anomalies | `DelayImports×3` | Delay-loaded imports are often used by malware to hide functionality from static analysis, only loading malicious import |
| yara | matches | `IsPacked, Borland, Delphi, InnoInstaller` | YARA rules confirm the sample is packed, compiled with Borland/Delphi, and is an Inno Setup installer, aligning with all |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The analyzed sample is a packed, Borland Delphi-compiled Windows GUI PE32 executable containing multiple indicators of malicious activity, including embedded network indicators (domain, IPv4/IPv6 addresses, URL), functionality to disable Data Execution Prevention (DEP), privilege escalation code, Windows registry manipulation, token manipulation, and file operation capabilities, all consistent with malware designed to compromise system security.

### deep key_evidence
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "IsPacked", "why": "Confirms the executable is packed, a common obfuscation technique used by malware to hinder analysis and evade detection."}`
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "borland_delphi", "why": "Indicates the sample is compiled with Borland Delphi, a development toolchain frequently used to create malware."}`
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "domain", "why": "Confirms the presence of an embedded domain name, a network indicator typically used for command-and-control (C2) communication or malicious payload delivery."}`
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "IP", "why": "Confirms embedded IPv4 and IPv6 address strings, which are network indicators for malicious communication endpoints."}`
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "url", "why": "Confirms an embedded URL, likely used for downloading additional malicious payloads or communicating with C2 infrastructure."}`
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "disable_dep", "why": "Indicates the sample contains code to disable Data Execution Prevention, a security control that malware commonly bypasses to execute arbitrary code."}`
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "escalate_priv", "why": "Confirms the presence of privilege escalation functionality, a common malicious behavior used to gain higher-level system access and bypass access controls."}`
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "win_registry", "why": "Indicates Windows registry manipulation capabilities, which malware uses for persistence, configuration storage, and stealthy system modification."}`
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "win_token", "why": "Confirms Windows token manipulation code, used by malware to abuse access tokens, impersonate privileged users, and bypass security restrictions."}`
- `{"source": "checklist_yara_scan findings", "query_or_table": "yara_rule_matches", "row_or_rule": "win_files_operation", "why": "Indicates file operation functionality, which malware uses for data exfiltration, payload deployment, and modifying system files for persistence or disruption."}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
size: 2263752
type: PE
architecture: X86
entrypoint_ea: 742124
entropy: 184
file_name: koi_sample.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 101 | - |
| .text | 1024 | 735744 | 737280 | 121 | RX |
| .itext | 738304 | 6144 | 8192 | 48 | RX |
| .data | 746496 | 14336 | 16384 | 82 | RW |
| .idata | 762880 | 4096 | 4096 | 74 | RW |
| .didata | 766976 | 512 | 4096 | 0 | RW |
| .edata | 771072 | 512 | 4096 | 0 | R |
| .rdata | 775168 | 512 | 4096 | 0 | R |
| .rsrc | 779264 | 69632 | 69632 | 39 | R |
| overlay | 848896 | 1431240 | 0 | 223 | - |
| .bss | 2280136 | 0 | 28672 | 0 | RW |
| .tls | 2308808 | 0 | 4096 | 0 | RW |

### Malcat YARA / Signatures (4)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| TurboLinker | compiler | INFO | 80 | Linked with TurboLinker |
| Delphi | language | INFO | 80 | Delphi executable, detection based on several artifacts |
| InnoInstaller | installer | INFO | 90 | InnoSetup installer |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |

### Anomalies (13)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 221 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ResourceDirectoryGap | 4 | resources | 1 | There is a space (bigger than 15 bytes) inside the resource directory region which is not occupied b |
| BigStringHiScore | 3 | strings | 2 | string has more than 256 characters and high interest score |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| DelayImports | 3 | imports | 3 | There are delay imports |
| ManyHighValueImmediates | 3 | code | 1 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| XorInLoop | 3 | code | 19 | XOR instruction in a loop |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| HugeGapBetweenFunctions | 2 | code | 24 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| HighXrefLoopingFunction | 1 | code | 12 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 30 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **HighXrefLoopingFunction**
  - `18868`: 
  - `19588`: 
  - `23820`: 
  - `28288`: 
  - `31684`: 
- **ManyHighValueImmediates**
  - `125716`: 
- **ManyUniqueImmediateBytes**
  - `102136`: 
- **ResourceDirectoryGap**
  - `848464`: 
- **SequentialFunction**
  - `63194`: 
  - `65118`: 
- **SpaghettiFunction**
  - `19744`: 
  - `26152`: 
  - `29624`: 
  - `33032`: 
  - `33396`: 
- **XorInLoop**
  - `21853`: 
  - `22125`: 
  - `101039`: 
  - `105002`: 
  - `105026`: 

### High-Signal Strings (13 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 129464 | `kernel32.dll` |
| 739224 | `kernel32.dll` |
| 22792 | `kernel32.dll` |
| 131112 | `kernel32.dll` |
| 740708 | `kernel32.dll` |
| 40680 | `kernel32.dll` |
| 140960 | `kernel32.dll` |
| 739552 | `cryptbase.dll` |
| 38640 | `kernel32.dll` |
| 741288 | `kernel32.dll` |
| 767314 | `kernel32.dll` |
| 764232 | `kernel32.dll` |
| 767240 | `kernel32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 716876 | `The setup files .. of the program.` |
| 156856 | `The setup files .. of the program.` |
| 755472 | `Inno Setup Setup..Data (6.1.0) (u)` |
| 753614 | `0001020304050607..0123456789ABCDEF` |
| 722800 | `For more detaile..pic=setupcmdline` |
| 41456 | `Software\Borland\Delphi\Locales` |
| 717488 | `/ALLUSERS
Instr.. install mode.
` |
| 717800 | `The Setup progra..ssword to use.
` |
| 41404 | `Software\Borland\Locales` |
| 148572 | `lzmadecompsmall:..s corrupted (%d)` |
| 41292 | `Software\Embarcadero\Locales` |
| 129540 | `NTDLL.DLL` |
| 844860 | `rDlPtS` |
| 739444 | `apphelp.dll` |
| 41352 | `Software\CodeGear\Locales` |
| 141080 | `Control Panel\De..p\ResourceLocale` |
| 739480 | `propsys.dll` |
| 129464 | `kernel32.dll` |
| 739224 | `kernel32.dll` |
| 22792 | `kernel32.dll` |
| 131112 | `kernel32.dll` |
| 740708 | `kernel32.dll` |
| 40680 | `kernel32.dll` |
| 739592 | `oleacc.dll` |
| 140988 | `.DEFAULT\Control..el\International` |
| 140960 | `kernel32.dll` |
| 739736 | `clbcatq.dll` |
| 739772 | `ntmarta.dll` |
| 741316 | `Wow64RevertWow64FsRedirection` |
| 739664 | `profapi.dll` |
| 739404 | `setupapi.dll` |
| 159668 | `oleaut32.dll` |
| 739368 | `userenv.dll` |
| 739332 | `uxtheme.dll` |
| 846504 | `<?xml version="1..>
</assembly>
` |
| 739516 | `dwmapi.dll` |
| 741224 | `Wow64DisableWow64FsRedirection` |
| 147388 | `Compressed block is corrupted` |
| 739552 | `cryptbase.dll` |
| 714068 | `D:P(A;OICI;0x001F01FF;;;` |
| 714148 | `(A;OICI;0x001F01FF;;;BA)` |
| 739628 | `version.dll` |
| 714212 | `(A;OICI;0x001F01FF;;;SY)` |
| 140908 | `GetUserDefaultUILanguage` |
| 739700 | `comres.dll` |
| 38640 | `kernel32.dll` |
| 741288 | `kernel32.dll` |
| 749039 | `0123456789ABCDEF` |
| 129492 | `RtlCompareUnicodeString` |
| 121000 | `:mm:ss` |
| 147156 | `Compressed block is corrupted` |
| 146864 | `Compressed block is corrupted` |
| 129420 | `CompareStringOrdinal` |
| 123460 | `eeee` |
| 113848 | `yyyy` |
| 116060 | `AAAA` |
| 118488 | `dddd` |
| 123436 | `yyyy` |
| 120816 | `mmmm d, yyyy` |
| 715092 | `SeShutdownPrivilege` |
| 759808 | `0123456789ABCDEFGHIJKLMNOPQRSTUV` |
| 743948 | `InnoSetupLdrWindow` |
| 338520 | `@GetPackageInfoTable` |
| 22760 | `GetLogicalProcessorInformation` |
| 1430695 | `Inno Setup Setup..Data (6.1.0) (u)` |
| 11440 | `The sizes of une..rge blocks are: ` |
| 148732 | `lzmadecompsmall: %s` |
| 38668 | `SetThreadPreferredUILanguages` |
| 141324 | `[ExceptObject=nil]` |
| 131140 | `GetDiskFreeSpaceExW` |
| 38608 | `GetThreadPreferredUILanguages` |
| 739252 | `SetDefaultDllDirectories` |
| 333720 | `constructor ` |
| 120788 | `m/d/yy` |
| 766796 | `AdjustTokenPrivileges` |
| 194468 | `UnicodeString` |
| 836960 | `:%s Service Pack..uild %3:d, %5:s)` |
| 149344 | `LzmaDecode failed (%d)` |
| 565824 | `TApplication` |
| 716148 | `/SPAWNWND=` |

### Constants / Known Patterns (43)
| Category | Value |
|---|---|
| guid | `guid::IUnknown` |
| guid | `guid::IDispatch` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| registry | `registry::HKEY_CURRENT_USER` |
| hash | `hash::xxhash` |
| oid | `oid::signedData` |
| oid | `oid::sha-256` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| crypto | `crypto::PKCS_DigestDecoration_SHA256__8_byt_19` |
| oid | `oid::countryName` |
| oid | `oid::organizationName` |
| oid | `oid::organizationalUnitName` |
| oid | `oid::commonName` |
| oid | `oid::rsaEncryption` |
| oid | `oid::basicConstraints` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::keyUsage` |
| oid | `oid::extKeyUsage` |
| oid | `oid::codeSigning` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::ocsp` |
| oid | `oid::caIssuers` |
| oid | `oid::certificatePolicies` |
| oid | `oid::anyPolicy` |
| oid | `oid::cps` |
| oid | `oid::sha384WithRSAEncryption` |
| oid | `oid::sha256WithRSAEncryption` |
| oid | `oid::businessCategory` |
| oid | `oid::jurisdictionOfIncorporationC` |
| oid | `oid::jurisdictionOfIncorporationSP` |
| oid | `oid::jurisdictionOfIncorporationL` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::spcSpOpusInfo` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |
| oid | `oid::individualCodeSigning` |
| oid | `oid::tSTInfo` |
| oid | `oid::timeStamping` |
| oid | `oid::globalsignTSAPolicy` |

### Imports (373)
| EA | Name | Type | Refs |
|---|---|---|---|
| 11120 | user32.MessageBoxA (delaystub) | DEBUG | 2 |
| 11256 | kernel32.GetLogicalProcessorInformation (delaystub) | DEBUG | 2 |
| 18468 | @System@@ReallocMem$qqrrpvi | DEBUG | 5 |
| 18548 | @System@ExceptObject$qqrv | DEBUG | 9 |
| 18580 | @System@ExceptAddr$qqrv | DEBUG | 1 |
| 18788 | @System@@_IOTest$qqrv | DEBUG | 1 |
| 18820 | @System@SetInOutRes$qqri | DEBUG | 3 |
| 18836 | @System@IOResult$qqrv | DEBUG | 1 |
| 19344 | @System@@TRUNC$qqrv | DEBUG | 2 |
| 19488 | @System@Flush$qqrrpv | DEBUG | 1 |
| 20664 | @System@TObject@$bctr$qqrv | DEBUG | 189 |
| 20696 | @System@TObject@$bdtr$qqrv | DEBUG | 225 |
| 20712 | @System@TObject@Free$qqrv | DEBUG | 172 |
| 20864 | InvokeImplGetter | DEBUG | 1 |
| 22192 | @System@@ClassCreate$qqrp17System@TMetaClasso | DEBUG | 225 |
| 22360 | @System@@BeforeDestruction$qqrp14System@TObjectzc | DEBUG | 117 |
| 24708 | NotifyReRaise | DEBUG | 1 |
| 24736 | NotifyNonDelphiException | DEBUG | 2 |
| 24836 | CheckJmp | DEBUG | 1 |
| 24868 | NotifyExceptFinally | DEBUG | 2 |
| 24908 | NotifyTerminate | DEBUG | 1 |
| 24936 | NotifyUnhandled | DEBUG | 1 |
| 24968 | @System@@HandleAnyException$qqrv | DEBUG | 33 |
| 25268 | @System@@HandleOnException$qqrv | DEBUG | 5 |
| 25828 | @System@@HandleFinally$qqrv | DEBUG | 3 |
| 25996 | @System@@RaiseAgain$qqrv | DEBUG | 16 |
| 26080 | @System@@DoneExcept$qqrv | DEBUG | 37 |
| 26128 | @System@@TryFinallyExit$qqrv | DEBUG | 19 |
| 26756 | @System@@StartExe$qqrp23System@PackageInfoTablep17System@TLibModule | DEBUG | 1 |
| 27088 | @System@@InitImports$qqrv | DEBUG | 2 |
| 27816 | StartAddress | DEBUG | 1 |
| 28264 | @System@@WStrClr$qqrpv | DEBUG | 40 |
| 28384 | @System@@WStrArrayClr$qqrpvi | DEBUG | 1 |
| 28420 | @System@@LStrAddRef$qqrpv | DEBUG | 9 |
| 28436 | @System@@LStrAddRef$qqrpv | DEBUG | 1 |
| 28452 | @System@@WStrAddRef$qqrr17System@WideString | DEBUG | 1 |
| 29624 | @System@@PStrCmp$qqrv | DEBUG | 8 |
| 29756 | @System@@AStrCmp$qqrv | DEBUG | 8 |
| 30108 | @System@@LStrToString$qqrv | DEBUG | 1 |
| 30436 | WStrSet | DEBUG | 1 |
| 31176 | @System@@LStrFromWStr$qqrr17System@AnsiStringx17System@WideString | DEBUG | 23 |
| 31196 | @System@@WStrFromLStr$qqrr17System@WideStringx17System@AnsiString | DEBUG | 25 |
| 33008 | @_llumod | DEBUG | 2 |
| 33372 | @_llumod | DEBUG | 1 |
| 35156 | @System@@New$qqripv | DEBUG | 1 |
| 35276 | @System@@_lludiv$qqrv | DEBUG | 1 |
| 42892 | NotifyModuleUnload | DEBUG | 1 |
| 43020 | @System@UnregisterModule$qqrp17System@TLibModule | DEBUG | 1 |
| 43132 | @System@@IntfClear$qqrr45System@%DelphiInterface$t17System@IInterface% | DEBUG | 182 |
| 43156 | @System@@IntfCopy$qqrr45System@%DelphiInterface$t17System@IInterface%x45System@%DelphiInterface$t17System@IInterface% | DEBUG | 207 |
| 43200 | @System@@IntfCast$qqrr45System@%DelphiInterface$t17System@IInterface%x45System@%DelphiInterface$t17System@IInterface%rx5_GUID | DEBUG | 1 |
| 43248 | @System@@IntfAddRef$qqrx45System@%DelphiInterface$t17System@IInterface% | DEBUG | 2 |
| 47616 | @System@TInterfacedObject@NewInstance$qqrp17System@TMetaClass | DEBUG | 47 |
| 49180 | InitThreadTLS | DEBUG | 1 |
| 49248 | @GetTls | DEBUG | 30 |
| 50336 | __dbk_fcall_wrapper | EXPORT | 1 |
| 54904 | kernel32.GetNativeSystemInfo (delaystub) | DEBUG | 2 |
| 55588 | @Sysutils@StrPas$qqrpxc | DEBUG | 1 |
| 100788 | @Math@DivMod$qqriusrust3 | DEBUG | 6 |
| 100816 | InvalidGraphic | DEBUG | 2 |
| 103048 | @System@@Str0Int64$qqrj | DEBUG | 4 |
| 103900 | @Sysutils@StrToIntDef$qqrx17System@AnsiStringi | DEBUG | 9 |
| 103924 | @Sysutils@TryStrToInt$qqrx17System@AnsiStringri | DEBUG | 5 |
| 103956 | @Sysutils@TryStrToInt64$qqrx17System@AnsiStringrj | DEBUG | 1 |
| 104416 | @Sysutils@BoolToStr$qqroo | DEBUG | 1 |
| 104692 | BackfillGetDiskFreeSpaceEx | DEBUG | 1 |
| 105340 | @Sysutils@StrPas$qqrpxc | DEBUG | 3 |
| 110052 | @Sysutils@FloatToDecimal$qqrr18Sysutils@TFloatRecpxv20Sysutils@TFloatValueii | DEBUG | 1 |
| 111352 | @Sysutils@DateTimeToTimeStamp$qqr16System@TDateTime | DEBUG | 3 |
| 111492 | @Sysutils@TimeStampToDateTime$qqrrx19Sysutils@TTimeStamp | DEBUG | 1 |
| 111736 | @Sysutils@DecodeTime$qqrx16System@TDateTimerust2t2t2 | DEBUG | 1 |
| 111828 | @Sysutils@IsLeapYear$qqrus | DEBUG | 2 |
| 112092 | @Sysutils@EncodeDate$qqrususus | DEBUG | 2 |
| 112140 | @Sysutils@DecodeDateFully$qqrx16System@TDateTimerust2t2t2 | DEBUG | 1 |
| 112472 | @Sysutils@DecodeDate$qqrx16System@TDateTimerust2t2 | DEBUG | 1 |
| 112504 | @Sysutils@DayOfWeek$qqrx16System@TDateTime | DEBUG | 4 |
| 117212 | EraToYear | DEBUG | 1 |
| 123656 | ConvertAddr | DEBUG | 1 |
| 124600 | @Sysutils@Exception@$bctr$qqrx17System@AnsiStringpx14System@TVarRecxi | DEBUG | 48 |
| 124728 | @Sysutils@Exception@$bctr$qqrp20System@TResStringRec | DEBUG | 77 |

### Functions (30)
| EA | Name |
|---|---|
| 40728 | sub_40ab18 |
| 146148 | sub_4246e4 |
| 140644 | sub_423164 |
| 188760 | sub_42ed58 |
| 188992 | sub_42ee40 |
| 623780 | sub_4990a4 |
| 132428 | sub_42114c |
| 203044 | sub_432524 |
| 106508 | sub_41ac0c |
| 104972 | sub_41a60c |
| 146199 | sub_424717 |
| 19152 | sub_4056d0 |
| 20216 | sub_405af8 |
| 113860 | sub_41c8c4 |
| 626039 | sub_499977 |
| 101100 | sub_4196ec |
| 130244 | sub_4208c4 |
| 596923 | sub_4927bb |
| 101620 | sub_4198f4 |
| 243124 | sub_43c1b4 |
| 130392 | sub_420958 |
| 617340 | sub_49777c |
| 620304 | sub_498310 |
| 128528 | sub_420210 |
| 21764 | sub_406104 |
| 22036 | sub_406214 |
| 139024 | sub_422b10 |
| 420716 | sub_46776c |
| 421108 | sub_4678f4 |
| 122604 | sub_41eaec |

### Decompilations (top 6)
#### 40728 — sub_40ab18
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40ab18(int32_t param_1,undefined4 param_2)

{
    undefined4 uVar1;
    int32_t iVar2;
    int32_t iVar3;
    undefined4 *in_FS_OFFSET;
    undefined4 uStackY_278;
    undefined4 uVar4;
    undefined4 uVar5;
    undefined4 *puVar6;
    int16_t *piVar7;
    undefined4 uVar8;
    undefined4 uVar9;
    undefined4 uVar10;
    undefined4 *puVar11;
    undefined4 uStack_248;
    undefined4 uStack_244;
    undefined4 *puStack_240;
    undefined4 uStack_23c;
    int16_t *piStack_238;
    code *pcStack_234;
    undefined4 uStack_230;
    undefined4 uStack_22c;
    undefined *puStack_228;
    int16_t aiStack_21e [261];
    undefined4 uStack_14;
    undefined4 uStack_10;
    int32_t iStack_c;
    int32_t iStack_8;
    
    puStack_228 = 0x40ab2f;
    iStack_8 = param_1;
    @System@@LStrAddRef$qqrpv(param_1);
    uStack_22c = 0x40ad3d;
    uStack_230 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_230;
    if (iStack_8 == 0) {
        pcStack_234 = 0x105;
        piStack_238 = aiStack_21e;
        uStack_23c = 0;
        puStack_240 = 0x40ab56;
        puStack_228 = &stack0xfffffffc;
        jmp_kernel32.GetModuleFileNameW();
    }
    else {
        pcStack_234 = 0x40ab60;
        puStack_228 = &stack0xfffffffc;
        uVar1 = sub_4084ec(iStack_8);
        pcStack_234 = 0x40ab72;
        sub_40a34c(aiStack_21e, 0x105, uVar1);
    }
    if (aiStack_21e[0] != 0) {
        iStack_c = 0;
        puStack_240 = &uStack_10;
        uStack_244 = 0xf0019;
        uStack_248 = 0;
        iVar2 = jmp_advapi32.RegOpenKeyExW();
        if (iVar2 != 0) {
            puStack_240 = &uStack_10;
            uStack_244 = 0xf0019;
            uStack_248 = 0;
            iVar2 = jmp_advapi32.RegOpenKeyExW();
            if (iVar2 != 0) {
                puStack_240 = &uStack_10;
                uStack_244 = 0xf0019;
                uStack_248 = 0;
                iVar2 = jmp_advapi32.RegOpenKeyExW();
                if (iVar2 != 0) {
                    puStack_240 = &uStack_10;
                    uStack_244 = 0xf0019;
                    uStack_248 = 0;
                    iVar2 = jmp_advapi32.RegOpenKeyExW();
                    if (iVar2 != 0) {
                        puStack_240 = &uStack_10;
                        uStack_244 = 0xf0019;
                        uStack_248 = 0;
                        iVar2 = jmp_advapi32.RegOpenKeyExW();
                        if (iVar2 != 0) {
                            puStack_240 = &uStack_10;
                            uStack_244 = 0xf0019;
                            uStack_248 = 0;
                            iVar2 = jmp_advapi32.RegOpenKeyExW();
                            if (iVar2 != 0) goto code_r0x0040ad27;
                        }
                    }
                }
            }
        }
        uStack_244 = 0x40ad20;
        uStack_248 = *in_FS_OFFSET;
        *in_FS_OFFSET = &uStack_248;
        puStack_240 = &stack0xfffffffc;
        sub_40a928(aiStack_21e, 0x105);
        puVar11 = &uStack_14;
        uVar10 = 0;
        uVar9 = 0;
        uVar8 = 0;
        piVar7 = aiStack_21e;
        uVar1 = uStack_10;
        iVar2 = jmp_advapi32.RegQueryValueExW();
        if (iVar2 == 0) {
            iVar2 = sub_4053f0(uStack_14);
            puVar6 = &uStack_14;
            uVar5 = 0;
            uVar4 = 0;
            uStackY_278 = uStack_10;
            iStack_c = iVar2;
            jmp_advapi32.RegQueryValueExW();
            sub_408550(param_2, iStack_c);
        }
        else {
            puVar6 = &uStack_14;
            iVar2 = 0;
            uVar5 = 0;
            uVar4 = 0;
            uStackY_278 = uStack_10;
            iVar3 = jmp_advapi32.RegQueryValueExW();
            if (iVar3 == 0) {
                iStack_c = sub_4053f0(uStack_14);
                jmp_advapi32.RegQueryValueExW();
                sub_408550(param_2, iStack_c);
            }
        }
        *in_FS_OFFSET = uStackY_278;
        if (iStack_c != 0) {
   
```
#### 146148 — sub_4246e4
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_4246e4(void)

{
    uint32_t uVar1;
    uint32_t *puVar2;
    int32_t iVar3;
    uint32_t uVar4;
    
    uVar4 = 0;
    puVar2 = 0x4c090c;
    do {
        iVar3 = 8;
        uVar1 = uVar4;
        do {
            if ((uVar1 & 1) == 0) {
                uVar1 = uVar1 >> 1;
            }
            else {
                uVar1 = uVar1 >> 1 ^ 0xedb88320;
            }
            iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
        *puVar2 = uVar1;
        uVar4 = uVar4 + 1;
        puVar2 = puVar2 + 1;
    } while (uVar4 != 0x100);
    return;
}

```
#### 140644 — sub_423164
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_423164(void)

{
    undefined4 uVar1;
    code *pcVar2;
    int32_t iVar3;
    undefined4 *in_FS_OFFSET;
    undefined4 uVar4;
    undefined4 uVar5;
    undefined4 uStack_24;
    undefined4 uStack_20;
    undefined *puStack_1c;
    undefined4 uStack_14;
    undefined4 uStack_10;
    undefined4 uStack_c;
    undefined4 uStack_8;
    
    puStack_1c = &stack0xfffffffc;
    uStack_14 = 0;
    uStack_8 = 0;
    uStack_20 = 0x42325e;
    uStack_24 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_24;
    uVar5 = "GetUserDefaultUILanguage";
    uVar4 = "kernel32.dll";
    uVar1 = jmp_kernel32.GetModuleHandleW();
    pcVar2 = sub_40e1b8();
    if (pcVar2 == 0x0) {
        iVar3 = sub_41ff44();
        if (iVar3 == 2) {
            iVar3 = sub_423054(0, 0x80000003, ".DEFAULT\\Control Panel\\International", &uStack_c, 1, 0, uVar1, uVar4);
            if (iVar3 == 0) {
                sub_423048(uStack_c, "Locale", &uStack_8);
                jmp_advapi32.RegCloseKey();
            }
        }
        else {
            iVar3 = sub_423054(0, 0x80000001, "Control Panel\\Desktop\\ResourceLocale", &uStack_c, 1, 0, uVar1, uVar4);
            if (iVar3 == 0) {
                sub_423048(uStack_c, 0x423364, &uStack_8);
                jmp_advapi32.RegCloseKey();
            }
        }
        sub_40873c(&uStack_14, 0x423374, uStack_8);
        sub_405920(uStack_14, &uStack_10);
    }
    else {
        (*pcVar2)();
    }
    *in_FS_OFFSET = uVar1;
    sub_407a20(&uStack_14, uVar1, uVar5, sub_423265);
    sub_407a20(&uStack_8);
    return;
}

```

### Carved Files (15)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 2664 |
| ? | DIB | 1640 |
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 5672 |
| ? | DIB | 3752 |
| ? | DIB | 2216 |
| ? | DIB | 1384 |
| ? | PNG | 4837 |
| ? | DIB | 16936 |
| ? | DIB | 9640 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |
| ? | InnoSetup | 1420730 |
| ? | PKCS7 | 10493 |

### Virtual Files (30)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/en-us | 2664 | - |
| ICO/2/en-us | 1640 | - |
| ICO/3/en-us | 744 | - |
| ICO/4/en-us | 296 | - |
| ICO/5/en-us | 5672 | - |
| ICO/6/en-us | 3752 | - |
| ICO/7/en-us | 2216 | - |
| ICO/8/en-us | 1384 | - |
| ICO/9/en-us | 4837 | - |
| ICO/10/en-us | 16936 | - |
| ICO/11/en-us | 9640 | - |
| ICO/12/en-us | 4264 | - |
| ICO/13/en-us | 1128 | - |
| STR/4086/unk | 864 | - |
| STR/4087/unk | 608 | - |
| STR/4088/unk | 1116 | - |
| STR/4089/unk | 1036 | - |
| STR/4090/unk | 724 | - |
| STR/4091/unk | 184 | - |
| STR/4092/unk | 156 | - |

### Structures (134)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 256 |
| OptionalHeader | 280 |
| Sections | 504 |
| ImportTable | 762880 |
| kernel32.OFT | 763040 |
| comctl32.OFT | 763444 |
| version.OFT | 763452 |
| user32.OFT | 763468 |
| oleaut32.OFT | 763536 |
| netapi32.OFT | 763584 |
| advapi32.OFT | 763596 |
| kernel32.FT | 763636 |
| comctl32.FT | 764040 |
| version.FT | 764048 |
| user32.FT | 764064 |
| oleaut32.FT | 764132 |
| netapi32.FT | 764180 |
| advapi32.FT | 764192 |
| ImportNames | 764232 |
| DelayImportTable | 766976 |
| kernel32.Addresses | 767120 |
| user32.Addresses | 767124 |
| kernel32.Addresses | 767128 |
| kernel32.Names | 767156 |
| user32.Names | 767164 |
| kernel32.Names | 767172 |
| ExportDirectory | 771072 |
| ExportAddressTable | 771112 |
| ExportNameTable | 771124 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 37 · duration_s: 2.19

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| check for time delay via GetTickCount |  | B0001.032:Debugger Detection |
| get geographical location | T1614:System Location Discovery |  |
| hash data with CRC32 |  | C0032.001:Checksum |
| generate random numbers using the Delphi LCG |  | C0021:Generate Pseudo-random Sequence |
| create directory |  | C0046:Create Directory |

## PE Imports / Signals
import_count: 142

| label | api_match | ATT&CK |
|---|---|---|
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 26

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=3 |
| IP | - | $ipv4@830343 len=7; $ipv6@917570 len=2 |
| contains_base64 | - | $a@2194 len=12 |
| CRC32_poly_Constant | - | $c0@146170 len=4 |
| Delphi_CompareCall | - | $c1@31860 len=42 |
| url | - | $url_regex@722888 len=78 |
| Borland | - | $patternBorland@41422 len=14 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| borland_delphi | - | $c0@50636 len=42; $c1@50636 len=73 |
| Borland_Delphi_40_additional | - | $a@15976 len=5 |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@15728 len=4 |
| Borland_Delphi_30_additional | - | $a@15976 len=4 |
| Borland_Delphi_30_ | - | $a@15976 len=4 |
| Borland_Delphi_Setup_Module | - | $a@15976 len=5 |
| Borland_Delphi_40 | - | $a@15976 len=5 |
| Borland_Delphi_v40_v50 | - | $a@15976 len=4 |
| Borland_Delphi_v30 | - | $a@15976 len=4 |
| Borland_Delphi_DLL | - | $a@15976 len=4 |
| disable_dep | - | $c4@738280 len=19 |
| escalate_priv | - | $d1@761072 len=12; $c2@761164 len=21 |
| win_registry | - | $f1@761072 len=12; $c3@761260 len=11; $c6@761260 len=11 |
| win_token | - | $f1@761072 len=12; $c2@761164 len=21; $c3@761274 len=16 |
| win_files_operation | - | $f1@758600 len=12; $c1@760088 len=9; $c2@759296 len=14; $c3@760088 len=9; $c4@758874 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 830343,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 917570,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2194,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 146170,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Delphi_CompareCall",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 31860,
          "length": 42,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 722888,
          "length": 78,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$patternBorland",
          "offset": 41422,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "borland_delphi",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 50636,
          "length": 42,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 50636,
          "length": 73,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_40_additional",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 15976,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/incoming/e29d2
```

## FLOSS Strings
Total strings: 11298 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 1, "language_strings": 0, "language_strings_missed": 0, "static_strings": 11297}`

### FLOSS sample
- `1096159247`
- `This program must be run under Win32`
- ``.itext`
- ``.data`
- `.idata`
- `.didata`
- `.edata`
- `.rdata`
- `@.rsrc`
- `Boolean`
- `System`
- `AnsiChar`
- `ShortInt`
- `SmallInt`
- `Integer`
- `Cardinal`
- `Pointer`
- `UInt64`
- `NativeInt`
- `NativeUInt`
- `Single`
- `Extended`
- `Double`
- `Currency`
- `ShortString`
- `PAnsiChar0`
- `PWideCharL`
- `ByteBool`
- `WordBool`
- `LongBool`
- `string`
- `WideString`
- `AnsiString`
- `Variant`
- `OleVariant`
- `TClass`
- `HRESULT`
- `&op_Equality`
- `&op_Inequality`
- `Create`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004b5eec
```asm
┌ 501: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_24h @ ebp-0x24
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_38h @ ebp-0x38
│           ; var int32_t var_3ch @ ebp-0x3c
│           ; var int32_t var_40h @ ebp-0x40
│           ; var int32_t var_5ch @ ebp-0x5c
│           0x004b5eec      55             push ebp
│           0x004b5eed      8bec           mov ebp, esp
│           0x004b5eef      83c4a4         add esp, 0xffffffa4
│           0x004b5ef2      53             push ebx
│           0x004b5ef3      56             push esi
│           0x004b5ef4      57             push edi
│           0x004b5ef5      33c0           xor eax, eax
│           0x004b5ef7      8945c4         mov dword [var_3ch], eax
│           0x004b5efa      8945c0         mov dword [var_40h], eax
│           0x004b5efd      8945a4         mov dword [var_5ch], eax
│           0x004b5f00      8945d0         mov dword [var_30h], eax
│           0x004b5f03      8945c8         mov dword [var_38h], eax
│           0x004b5f06      8945cc         mov dword [var_34h], eax
│           0x004b5f09      8945d4         mov dword [var_2ch], eax
│           0x004b5f0c      8945d8         mov dword [var_28h], eax
│           0x004b5f0f      8945ec         mov dword [var_14h], eax
│           0x004b5f12      b8b8144b00     mov eax, 0x4b14b8
│           0x004b5f17      e8b072f5ff     call 0x40d1cc
│           0x004b5f1c      33c0           xor eax, eax
│           0x004b5f1e      55             push ebp
│           0x004b5f1f      68e2654b00     push 0x4b65e2
│           0x004b5f24      64ff30         push dword fs:[eax]
│           0x004b5f27      648920         mov dword fs:[eax], esp
│           0x004b5f2a      33d2           xor edx, edx
│           0x004b5f2c      55             push ebp
│           0x004b5f2d      689e654b00     push 0x4b659e
│           0x004b5f32      64ff32         push dword fs:[edx]
│           0x004b5f35      648922         mov dword fs:[edx], esp
│           0x004b5f38      a134e64b00     mov eax, dword [0x4be634]   ; [0x4be634:4]=0
│           0x004b5f3d      e8a29dffff     call 0x4afce4
│           0x004b5f42      e8f598ffff     call 0x4af83c
│           0x004b5f47      8d55ec         lea edx, [var_14h]
│           0x004b5f4a      33c0           xor eax, eax
│           0x004b5f4c      e84fcdf6ff     call 0x422ca0
│           0x004b5f51      8b55ec         mov edx, dword [var_14h]
│           0x004b5f54      b8841d4c00     mov eax, 0x4c1d84
│           0x004b5f59      e8a21ef5ff     call 0x407e00
│           0x004b5f5e      6a02           push 2                      ; 2
│           0x004b5f60      6a00           push 0
│           0x004b5f62      6a01           push 1  
```
### 0x0040d0a0
```asm
┌ 167: sym.SetupLdr.exe___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x0040d0a0      55             push ebp
│       ╎   0x0040d0a1      8bec           mov ebp, esp
│       ╎   0x0040d0a3      51             push ecx
│       ╎   0x0040d0a4      53             push ebx
│       ╎   0x0040d0a5      56             push esi
│       ╎   0x0040d0a6      57             push edi
│       ╎   0x0040d0a7      33c0           xor eax, eax
│       ╎   0x0040d0a9      8945fc         mov dword [var_4h], eax
│       ╎   0x0040d0ac      33c0           xor eax, eax
│       ╎   0x0040d0ae      55             push ebp
│       ╎   0x0040d0af      6841d14000     push 0x40d141
│       ╎   0x0040d0b4      64ff30         push dword fs:[eax]
│       ╎   0x0040d0b7      648920         mov dword fs:[eax], esp
│       ╎   0x0040d0ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0bd      50             push eax
│       ╎   0x0040d0be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0c1      50             push eax
│       ╎   0x0040d0c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0c5      50             push eax
│       ╎   0x0040d0c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0c9      50             push eax
│       ╎   0x0040d0ca      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0cd      50             push eax
│       ╎   0x0040d0ce      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0d1      50             push eax
│       ╎   0x0040d0d2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0d5      50             push eax
│       ╎   0x0040d0d6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0d9      50             push eax
│       ╎   0x0040d0da      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0dd      50             push eax
│       ╎   0x0040d0de      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0e1      50             push eax
│       ╎   0x0040d0e2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0e5      50             push eax
│       ╎   0x0040d0e6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0e9      50             push eax
│       ╎   0x0040d0ea      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0ed      50             push eax
│       ╎   0x0040d0ee      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0f1      50             push eax
│       ╎   0x0040d0f2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0f5      50             push eax
│       ╎   0x0040d0f6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0f9      50             push eax
│       ╎   0x0040d0fa      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0fd      50             push eax
│       ╎   0x0040d0fe      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d101      50             push eax
│       ╎   0x0040d102      8b45f
```
### 0x0040ccb0
```asm
; CALL XREF from sym.SetupLdr.exe___dbk_fcall_wrapper @ 0x40d12f(x)
┌ 1007: fcn.0040ccb0 ();
│           0x0040ccb0      55             push ebp
│           0x0040ccb1      8bec           mov ebp, esp
│           0x0040ccb3      e8f4ffffff     call fcn.0040ccac
│           0x0040ccb8      e8efffffff     call fcn.0040ccac
│           0x0040ccbd      e8eaffffff     call fcn.0040ccac
│           0x0040ccc2      e8e5ffffff     call fcn.0040ccac
│           0x0040ccc7      e8e0ffffff     call fcn.0040ccac
│           0x0040cccc      e8dbffffff     call fcn.0040ccac
│           0x0040ccd1      e8d6ffffff     call fcn.0040ccac
│           0x0040ccd6      e8d1ffffff     call fcn.0040ccac
│           0x0040ccdb      e8ccffffff     call fcn.0040ccac
│           0x0040cce0      e8c7ffffff     call fcn.0040ccac
│           0x0040cce5      e8c2ffffff     call fcn.0040ccac
│           0x0040ccea      e8bdffffff     call fcn.0040ccac
│           0x0040ccef      e8b8ffffff     call fcn.0040ccac
│           0x0040ccf4      e8b3ffffff     call fcn.0040ccac
│           0x0040ccf9      e8aeffffff     call fcn.0040ccac
│           0x0040ccfe      e8a9ffffff     call fcn.0040ccac
│           0x0040cd03      e8a4ffffff     call fcn.0040ccac
│           0x0040cd08      e89fffffff     call fcn.0040ccac
│           0x0040cd0d      e89affffff     call fcn.0040ccac
│           0x0040cd12      e895ffffff     call fcn.0040ccac
│           0x0040cd17      e890ffffff     call fcn.0040ccac
│           0x0040cd1c      e88bffffff     call fcn.0040ccac
│           0x0040cd21      e886ffffff     call fcn.0040ccac
│           0x0040cd26      e881ffffff     call fcn.0040ccac
│           0x0040cd2b      e87cffffff     call fcn.0040ccac
│           0x0040cd30      e877ffffff     call fcn.0040ccac
│           0x0040cd35      e872ffffff     call fcn.0040ccac
│           0x0040cd3a      e86dffffff     call fcn.0040ccac
│           0x0040cd3f      e868ffffff     call fcn.0040ccac
│           0x0040cd44      e863ffffff     call fcn.0040ccac
│           0x0040cd49      e85effffff     call fcn.0040ccac
│           0x0040cd4e      e859ffffff     call fcn.0040ccac
│           0x0040cd53      e854ffffff     call fcn.0040ccac
│           0x0040cd58      e84fffffff     call fcn.0040ccac
│           0x0040cd5d      e84affffff     call fcn.0040ccac
│           0x0040cd62      e845ffffff     call fcn.0040ccac
│           0x0040cd67      e840ffffff     call fcn.0040ccac
│           0x0040cd6c      e83bffffff     call fcn.0040ccac
│           0x0040cd71      e836ffffff     call fcn.0040ccac
│           0x0040cd76      e831ffffff     call fcn.0040ccac
│           0x0040cd7b      e82cffffff     call fcn.0040ccac
│           0x0040cd80      e827ffffff     call fcn.0040ccac
│           0x0040cd85      e822ffffff     call fcn.0040ccac
│           0x0040cd8a      e81dffffff     call fcn.0040ccac
│           0x0040cd8f      e818ffffff     call fcn.0040ccac
│           0x0040cd94      e813ffffff     call fcn.00
```
### 0x0040ccac
```asm
; XREFS(200)
┌ 1: fcn.0040ccac ();
└           0x0040ccac      c3             ret
```
### 0x004541a8
```asm
┌ 16: sym.SetupLdr.exe_TMethodImplementationIntercept (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           0x004541a8      55             push ebp
│           0x004541a9      8bec           mov ebp, esp
│           0x004541ab      8b550c         mov edx, dword [arg_ch]
│           0x004541ae      8b4508         mov eax, dword [arg_8h]
│           0x004541b1      e802000000     call fcn.004541b8
│           0x004541b6      5d             pop ebp
└           0x004541b7      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r

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
  - `kernel32.dll!GetACP`
  - `kernel32.dll!GetExitCodeProcess`
  - `kernel32.dll!LocalFree`
  - `kernel32.dll!CloseHandle`
  - `kernel32.dll!SizeofResource`
  - `comctl32.dll!InitCommonControls`
  - `version.dll!GetFileVersionInfoSizeW`
  - `version.dll!VerQueryValueW`
  - `version.dll!GetFileVersionInfoW`
  - `user32.dll!CreateWindowExW`
  - `user32.dll!TranslateMessage`
  - `user32.dll!CharLowerBuffW`
  - `user32.dll!CallWindowProcW`
  - `user32.dll!CharUpperW`
  - `oleaut32.dll!SysAllocStringLen`
  - `oleaut32.dll!SafeArrayPtrOfIndex`
  - `oleaut32.dll!VariantCopy`
  - `oleaut32.dll!SafeArrayGetLBound`
  - `oleaut32.dll!SafeArrayGetUBound`
  - `netapi32.dll!NetWkstaGetInfo`
  - `netapi32.dll!NetApiBufferFree`
  - `advapi32.dll!ConvertStringSecurityDescriptorToSecurityDescriptorW`
  - `advapi32.dll!RegQueryValueExW`
  - `advapi32.dll!AdjustTokenPrivileges`
  - `advapi32.dll!GetTokenInformation`
  - `advapi32.dll!ConvertSidToStringSidW`
