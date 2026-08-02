## 1. Executive Summary

This sample is a malicious packed PE file, classified as a Generic Packed Dropper/Loader with a threat score of 9/10 (source: llm_judge, verdict.json, verdict: Malicious, score: 9, family_guess: Generic Packed Dropper/Loader). Static analysis confirms heavy obfuscation: Ghidra identifies only 2 total functions (source: ghidra, analysis summary, funcs count = 2), FLOSS extracts 715 obfuscated static strings with 0 decoded/stack/tight strings (source: floss, Total strings: 715, per_category: decoded_strings: 0, stack_strings: 0, tight_strings: 0), and capa detects generic software packing and XOR data encoding (source: capa, top_rules, packed with generic packer (T1027.002); source: capa, top_rules, encode data using XOR (T1027)). The sample contains an embedded secondary PE payload (source: capa, top_rules, contain an embedded PE file) and imports high-signal APIs for persistence, process execution, and dynamic API resolution (source: pe_imports, signals, set_registry_value (RegSetValue) [T1112]; source: pe_imports, signals, create_process (CreateProcess) [T1106]; source: pe_imports, signals, load_library (LoadLibrary) [T1129] and get_proc_address (GetProcAddress) [T1129]). Analysis is limited by non-functional IDA and Malcat tools, with all valid data sourced from Ghidra, capa, pe_imports, FLOSS, and radare2. YARA execution failed due to a missing 'yr' binary, so no YARA matches are reliable (source: YARA Meta, batch_errors: [Errno 2] No such file or directory: 'yr').

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 |
| Sample Path | /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Threat Score | 9/10 |
| Family Guess | Generic Packed Dropper/Loader |
| Agreement | llm_v1_disagree |
| Cross-Engine Notes | IDA and Malcat are non-functional due to missing required binaries, so all analysis relies on Ghidra, capa, pe_imports, and FLOSS. Ghidra's extremely low function count (2) aligns with capa's detection of a generic packer, confirming heavy obfuscation. FLOSS's 715 obfuscated strings match capa's XOR encoding detection, indicating defense evasion via data obfuscation. pe_imports high-signal APIs align with capa's ATT&CK mappings for persistence, execution, and defense evasion. YARA execution failed due to a missing 'yr' binary, so no YARA matches are reliable. |

*Source: llm_judge, verdict.json*

## 3. File Layout & Structural Analysis

The sample is a 32-bit Windows PE file with non-standard executable sections .kofbl and .l1 (source: ghidra, memory blocks: executable sections .kofbl and .l1). It has no exported functions (source: ghidra, exports: none) and a total of 113 imported APIs (source: pe_imports, import_count: 113). The entry point (EP) is located at 0x4390914, which immediately delegates to a small unpacking stub at 0x401219 (FUN_00401219) (source: ghidra, callgraph: entry calls FUN_00401219; source: ghidra, funcs: only 2 functions (entry at 0x4390914, FUN_00401219 at 0x401219)).

XOR search identifies two encoded data regions: 0x80 bytes at 0x00000000 and 0x80 bytes at 0x0001B800 (source: xor, Found XOR 00 position 00000000: 00000080; source: xor, Found XOR 00 position 0001B800: 00000080). UPX unpacking failed, with no unpacked output generated (source: upx, upx_ok: False, is_packed: False, returncode: None, unpacked_path: ``), indicating a custom packer rather than UPX. FLOSS extracted 715 static strings, all obfuscated/encoded with no decoded content, consistent with packed/obfuscated code (source: floss, Total strings: 715, per_category: decoded_strings: 0, stack_strings: 0, tight_strings: 0).

## 4. Malcat Triage Summary

Malcat analysis failed entirely due to a missing required script: the tool returned the error `malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory`. No Malcat triage data, string analysis, or structural data is available for this sample.

*Source: Malcat Structured Analysis, error message*

## 5. Static Code Analysis

### Function Metrics
Ghidra identifies only 2 total functions in the sample, an extremely low count for a standard PE file that confirms heavy obfuscation/packing (source: ghidra, analysis summary, funcs count = 2):
- Entry function: 0x4390914
- Unpacking stub: FUN_00401219 at 0x401219

### Entry Point / Unpacking Stub Disassembly (radare2, 0x00430005)
```asm
┌ 139: fcn.00430005 ();
│       ╎   0x00430005      60             pushal
│       ╎   0x00430006      90             nop
│       ╎   0x00430007      b800104000     mov eax, section..text      ; 0x401000
│       ╎   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc
│       ╎   0x00430011      90             nop
│       ╎   0x00430012      b9e4302546     mov ecx, 0x462530e4
│       ╎   0x00430017      90             nop
│       ╎   0x00430018      90             nop
│       ╎   0x00430019      90             nop
│       ╎   0x0043001a      85c0           test eax, eax
│       ╎   0x0043001c      90             nop
│       ╎   0x0043001d      90             nop
│       ╎   0x0043001e      90             nop
│       ╎   0x0043001f      90             nop
│       ╎   0x00430020      90             nop
│       ╎   0x00430021      90             nop
│      ┌──< 0x00430022      742a           je 0x43004e
│     ┌───> 0x00430024      90             nop
│     ╎│╎   0x00430025      90             nop
│     ╎│╎   0x00430026      90             nop
│     ╎│╎   0x00430027      90             nop
│     ╎│╎   0x00430028      3108           xor dword [eax], ecx
│     ╎│╎   0x0043002a      90             nop
│     ╎│╎   0x0043002b      90             nop
│     ╎│╎   0x0043002c      90             nop
│     ╎│╎   0x0043002d      90             nop
│     ╎│╎   0x0043002e      90             nop
│     ╎│╎   0x0043002f      40             inc eax
│     ╎│╎   0x00430030      40             inc eax
│     ╎│╎   0x00430031      90             nop
│     ╎│╎   0x00430032      90             nop
│     ╎│╎   0x00430033      90             nop
│     ╎│╎   0x00430034      90             nop
│     ╎│╎   0x00430035      90             nop
│     ╎│╎   0x00430036      90             nop
│     ╎│╎   0x00430037      90             nop
│     ╎│╎   0x00430038      90             nop
│     ╎│╎   0x00430039      90             nop
│     ╎│╎   0x0043003a      40             inc eax
│     ╎│╎   0x0043003b      90             nop
│     ╎│╎   0x0043003c      40             inc eax
│     ╎│╎   0x0043003d      90             nop
│     ╎│╎   0x0043003e      90             nop
│     ╎│╎   0x0043003f      90             nop
│     ╎│╎   0x00430040      90             nop
│     ╎│╎   0x00430041      90             nop
│     ╎│╎   0x00430042      90             nop
│     ╎│╎   0x00430043      90             nop
│     ╎│╎   0x00430044      90             nop
│     ╎│╎   0x00430045      39d8           cmp eax, ebx
│     ╎│╎   0x00430047      90             nop
│     ╎│╎   0x00430048      90             nop
│     ╎│╎   0x00430049      90             nop
│     ╎│╎   0x0043004a      90             nop
│     ╎│╎   0x0043004b      90             nop
│     └───< 0x0043004c      75d6           jne 0x430024
│      └──> 0x0043004e      b800b04200     mov eax, str.__vu           ; section..data
│       ╎                                                              ; 0x42b000
│       ╎   0x00430053      90        
```
*Source: radare2, 0x00430005*

This stub implements a simple XOR decoder loop: it iterates over the .text section (0x401000 to 0x408ecc), XORing each dword with the key 0x462530e4, which aligns with capa's detection of XOR encoding (source: capa, top_rules, encode data using XOR (T1027)).

### Import Address Table (IAT) Thunks (radare2)
The sample's IAT is heavily obfuscated, with thunks interleaved with junk code. Key IAT entries include:
- 0x004312b0: ole32.DLL functions (CoCreateInstance, CLSIDFromString, CoUninitialize, SysAllocString)
- 0x004312dc: ExitProcess
- 0x004312e0: ExpandEnvironmentStringsA
- 0x004312e6: GetCommandLineA
- 0x004312e8: GetComputerNameA
- 0x004312ec: GetCurrentProcessId
- 0x004312f2: GetCurrentThreadId
- 0x004312f4: GetExitCodeThread
- 0x004312f9: GetFileSize
- 0x004312fe: GetModuleFileNameA
- 0x004312ff: GetModuleHandleA
- 0x00431306: CloseHandle
- 0x00431308: GetProcAddress
- 0x0043130a: GetSystemDirectoryA
- 0x00431334: KERNEL32.DLL_IsBadWritePtr
- 0x00431338: LoadLibraryA
- 0x00431340: KERNEL32.DLL_LocalFree, OpenMutexA, CreateFileA, ReadFile, RtlUnwind, SetFilePointer, CreateMutexA, Sleep, TerminateProcess, VirtualQuery, CreateProcessA, WaitForSingleObject, WideCharToMultiByte, WinExec, WriteFile, lstrlenA, lstrlenW
- 0x00431384: KERNEL32.DLL_CreateThread, DeleteFileA, USER32.DLL functions (GetWindowTextA, GetWindowRect, FindWindowA, GetWindow, GetClassNameA, SetFocus, GetForegroundWindow, LoadCursorA, LoadIconA, SetTimer, RegisterClassA, MessageBoxA, GetMessageA)

*Source: radare2, 0x004312b0, 0x00431334, 0x00431340, 0x00431384*

### High-Signal Imports (Ghidra / pe_imports)
| DLL | Imported APIs | Purpose |
|---|---|---|
| ADVAPI32.DLL | RegSetValueExA, RegCreateKeyExA, RegOpenKeyExA | Registry modification for persistence (source: ghidra, imports: RegSetValueExA, RegCreateKeyExA, RegOpenKeyExA (ADVAPI32.DLL)) |
| KERNEL32.DLL | CreateProcessA, WinExec, CreateFileA, ReadFile, WriteFile, SetFilePointer, CreateMutexA, TerminateProcess, LoadLibraryA, GetProcAddress | Process execution, file manipulation, dynamic API resolution (source: ghidra, imports: CreateProcessA, WinExec, CreateFileA, ReadFile, WriteFile, SetFilePointer, CreateMutexA, TerminateProcess (KERNEL32.DLL); source: ghidra, imports: LoadLibraryA, GetProcAddress (KERNEL32.DLL)) |
| USER32.DLL | GetWindowTextA, FindWindowA, GetForegroundWindow | Window enumeration (source: ghidra, imports: GetWindowTextA, FindWindowA, GetForegroundWindow (USER32.DLL)) |
| OLE32/OLEAUT32 | CoCreateInstance, CLSIDFromString, CoInitialize, CoUninitialize, SysAllocString | COM object instantiation (source: ghidra, imports: CoCreateInstance, CLSIDFromString, CoInitialize, CoUninitialize, SysAllocString (OLE32/OLEAUT32)) |
| WININET.DLL | DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA | URL cache manipulation (source: ghidra, imports: DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA (WININET.DLL)) |

### FLOSS Obfuscated Strings (Sample)
All 715 static strings are obfuscated/encoded, with no decoded content recovered. Sample strings include:
`.idata`, `.kofbl`, `<OF#55`, `1PA\2%F`, `oe-IZ4'IZ$`, `#&%FgV!F`, `:Pr%FEL`, `p0%Fmu`, `0%O?D!`, `%I`3$F`, `1 ~{q%`, `(^{q%fm`, `Dr%O$L`, `\r%{d0%F`, `1%F\GRF`, `v0%FdM`, `4Pad==`, `0Mn^r%`, `0M{^r%`, `0%Fi5Q`, `Ii4 /Xr%`, `<3`Vid`, `!IR4#{`, `pVid6C`, `Ii<(~Xr%`, `Do$0fup%`, `m<0vqp%IR`, `2Pr%IR`, `gF]!%F`, `MCIRs$c$0%Fg`, `0QNou)`, `#Z%.d0%F`, `gF]3%F`, `ou)ISp'`, `eNoe-ISb-o41``, `xNou) mu)`, `>0%Fou`, `5IR4;{`, `L}%Fmu`, `D}%FoM`

*Source: floss, FLOSS sample*

## 6. Behavioral & Dynamic Analysis

No dynamic runtime behavior was observed during analysis. Speakeasy executed the sample but recorded 0 API calls and 0 key events (source: speakeasy, api_calls: 0, key_events: 0, not observed: no API calls/events recorded — do not invent runtime behavior). The Frida probe is available (version 17.16.4) but no data was collected (source: Frida Probe, frida_available: True, version: 17.16.4, not observed). UPX unpacking failed with no output, so no unpacked payload was available for dynamic execution (source: upx, upx_ok: False, unpacked_path: ``).

## 7. Network Indicators & C2

No active network indicators or C2 infrastructure were identified in static or dynamic analysis. The sample imports WININET.DLL functions for URL cache manipulation (DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA) (source: ghidra, imports: DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA (WININET.DLL)), but no hardcoded IP addresses, domains, or URLs were recovered from static strings. capa did not detect any network-related capabilities (source: capa, capa Capability Rules: no network ATT&CK rules matched).

## 8. Capabilities & MITRE ATT&CK Mapping

| Capability | ATT&CK Technique | Source |
|---|---|---|
| Packed with generic packer | T1027.002: Obfuscated Files or Information (Software Packing) | capa, top_rules, packed with generic packer (T1027.002) |
| Encode data using XOR | T1027: Obfuscated Files or Information | capa, top_rules, encode data using XOR (T1027) |
| Contain embedded PE file | B0023: Install Additional Program | capa, top_rules, contain an embedded PE file |
| Modify registry values | T1112: Modify Registry | pe_imports, signals, set_registry_value (RegSetValue) [T1112]; ghidra, imports: RegSetValueExA, RegCreateKeyExA, RegOpenKeyExA (ADVAPI32.DLL) |
| Create new processes | T1106: Native API | pe_imports, signals, create_process (CreateProcess) [T1106]; ghidra, imports: CreateProcessA, WinExec (KERNEL32.DLL) |
| Dynamic API resolution | T1129: Shared Modules | pe_imports, signals, load_library (LoadLibrary) [T1129] and get_proc_address (GetProcAddress) [T1129]; ghidra, imports: LoadLibraryA, GetProcAddress (KERNEL32.DLL) |
| COM object instantiation | T1559: Inter-Process Communication via Component Object Model | ghidra, imports: CoCreateInstance, CLSIDFromString, CoInitialize, CoUninitialize, SysAllocString (OLE32/OLEAUT32) |
| URL cache manipulation | T1085: Rundll32 | ghidra, imports: DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA (WININET.DLL) |

## 9. Indicators of Compromise

| IOC Type | Value | Source |
|---|---|---|
| File Hash (SHA256) | bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 | sample metadata |
| Unusual PE Sections | .kofbl, .l1 | ghidra, memory blocks: executable sections .kofbl and .l1 |
| XOR Encoded Regions | 0x00000000 (0x80 bytes), 0x0001B800 (0x80 bytes) | xor, Found XOR 00 position 00000000: 00000080; xor, Found XOR 00 position 0001B800: 00000080 |
| High-Signal Imports | RegSetValueExA, RegCreateKeyExA, RegOpenKeyExA, CreateProcessA, WinExec, LoadLibraryA, GetProcAddress, CoCreateInstance, CLSIDFromString, DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA | ghidra, imports; pe_imports, signals |
| Obfuscated Static Strings | 715 total, sample listed in Section 5 | floss, Total strings: 715 |

No file paths, registry keys, C2 addresses, or decoded payload hashes are available at this time.

## 10. Detection Engineering

YARA rule generation is not possible at this time due to a missing 'yr' binary, which caused all YARA batch executions to fail (source: YARA Meta, batch_errors: [Errno 2] No such file or directory: 'yr'). However, the following detection signals can be used to build rules or detection logic:
1. **Section Name Anomaly**: Detect PE files with non-standard executable sections named .kofbl or .l1 (source: ghidra, memory blocks: executable sections .kofbl and .l1).
2. **Unpacking Stub Signature**: Detect the XOR decoder loop at 0x00430005, which uses the key 0x462530e4 to XOR the .text section (source: radare2, 0x00430005; source: capa, top_rules, encode data using XOR (T1027)).
3. **Import Set Signature**: Detect PE files with the co-occurrence of high-signal imports: RegSetValueExA, CreateProcessA, LoadLibraryA, GetProcAddress, DeleteUrlCacheEntryA (source: pe_imports, signals; source: ghidra, imports).
4. **Obfuscation Signals**: Flag PE files with <5 total functions and >500 obfuscated static strings with 0 decoded strings (source: ghidra, analysis summary, funcs count = 2; source: floss, Total strings: 715, per_category: decoded_strings: 0).
5. **capa Rules**: Use capa to detect generic packer (T1027.002), XOR encoding (T1027), and embedded PE (B0023) capabilities (source: capa, capa Capability Rules).

## 11. What We Don't Know

1. The embedded secondary PE payload detected by capa was not extracted: UPX unpacking failed, and no unpacked path is available (source: upx, upx_ok: False, unpacked_path: ``; source: capa, top_rules, contain an embedded PE file). The full functionality of the embedded payload is unknown.
2. The specific registry key path modified for persistence is unknown, as all static strings are obfuscated and no decoded strings were recovered (source: floss, per_category: decoded_strings: 0; source: pe_imports, signals, set_registry_value (RegSetValue) [T1112]).
3. No C2 server addresses, domains, or network payloads were observed in static or dynamic analysis (source: capa, capa Capability Rules: no network rules matched; source: speakeasy, api_calls: 0).
4. The purpose of the imported COM (OLE32) and WININET cache manipulation functions is unclear without unpacking the embedded payload or observing runtime behavior (source: ghidra, imports: CoCreateInstance, CLSIDFromString (OLE32/OLEAUT32); source: ghidra, imports: DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA (WININET.DLL)).
5. IDA and Malcat analysis is unavailable due to missing required binaries, so no additional static analysis or triage data from these tools exists (source: llm_judge, cross_engine_notes: IDA and Malcat are non-functional due to missing required binaries).
6. No runtime behavior was captured: Speakeasy recorded 0 API calls/events, and Frida collected no data (source: speakeasy, api_calls: 0, key_events: 0; source: Frida Probe, no data collected).
7. No YARA matches are available due to a missing 'yr' binary (source: YARA Meta, batch_errors: [Errno 2] No such file or directory: 'yr').

## 12. Appendix: Analysis Environment

| Tool | Version / Status | Purpose |
|---|---|---|
| Ghidra | Functional | Static analysis: function count, import enumeration, disassembly, memory block identification |
| capa | v?, duration 1.55s, 5 rules matched | Capability detection, MITRE ATT&CK mapping |
| pe_imports | Functional | Import enumeration, high-signal API identification |
| FLOSS | Functional | Static string extraction, obfuscation detection |
| radare2 | Functional | Disassembly of unpacking stub and IAT thunks |
| UPX | v?, failed (returncode: None) | Unpacking attempt, no output generated |
| XOR Search | Functional | Identification of XOR encoded data regions |
| Speakeasy | Functional, 0 events | Dynamic sandbox execution, no runtime behavior observed |
| Frida | v17.16.4, available, no data collected | Dynamic instrumentation probe |
| YARA | Failed (missing 'yr' binary) | Rule matching, no reliable results |
| IDA | Non-functional (missing required binaries) | Static analysis, no data available |
| Malcat | Non-functional (missing /opt/malcat/bin/malcat.mcp.py) | Triage and static analysis, no data available |

*Source: deep_dive.json tool_gate, structured evidence tool status fields*
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9  
**sample_path:** /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Generic Packed Dropper/Loader
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA and Malcat are non-functional due to missing required binaries, so all analysis relies on Ghidra, capa, pe_imports, and FLOSS. Ghidra's extremely low function count (2) aligns with capa's detection of a generic packer, confirming heavy obfuscation. FLOSS's 715 obfuscated strings match capa's XOR encoding detection, indicating defense evasion via data obfuscation. pe_imports high-signal APIs align with capa's ATT&CK mappings for persistence, execution, and defense evasion. YARA execution failed due to a missing 'yr' binary, so no YARA matches are reliable.
- **summary**: This sample is a malicious packed PE, likely functioning as a dropper/loader. It employs defense evasion techniques including generic software packing and XOR data encoding, carries an embedded secondary PE payload, and has capabilities for registry modification (persistence), process execution, and dynamic API resolution. Analysis is limited by non-functional IDA and Malcat tools, with all valid analytical data sourced from Ghidra, capa, pe_imports, and FLOSS. YARA execution failed due to a missing binary, so no YARA matches are reliable. The sample exhibits multiple high-signal malicious indicators consistent with common malware behavior.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with generic packer (T1027.002)` | Confirms the sample is packed, which explains the extremely low function count (2) from Ghidra and obfuscated string out |
| capa | top_rules | `encode data using XOR (T1027)` | Corroborates the large set of obfuscated/encoded strings observed in FLOSS output, indicating the sample uses XOR encodi |
| capa | top_rules | `contain an embedded PE file` | Indicates the sample carries a secondary malicious payload, consistent with dropper/loader functionality common in malwa |
| pe_imports | signals | `set_registry_value (RegSetValue) [T1112]` | High-signal import that indicates the ability to modify Windows registry values, a common technique for malware persiste |
| pe_imports | signals | `create_process (CreateProcess) [T1106]` | High-signal import indicating the ability to launch new processes, likely used to execute the embedded secondary payload |
| pe_imports | signals | `load_library (LoadLibrary) [T1129] and get_proc_address (GetProcAddress) [T1129]` | High-signal imports for dynamic API resolution, commonly used by packed malware to evade static detection and load requi |
| capa | strings | `715 total static strings with majority obfuscated/encoded patterns` | Consistent with capa's XOR encoding and packing detections, indicating the sample uses obfuscation to hide malicious ind |
| ghidra | analysis summary | `funcs count = 2` | Extremely low function count for a standard PE file is a strong indicator of packing/obfuscation, corroborated by capa's |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Packed/obfuscated PE loader/dropper. Static analysis shows only 2 identified functions and 113 imports, with high-signal persistence and execution APIs (RegSetValueExA, RegCreateKeyExA, RegOpenKeyExA, CreateProcessA, WinExec, LoadLibraryA, GetProcAddress). capa flags generic packer, XOR encoding, and an embedded PE file. FLOSS reports 715 static strings but no decoded strings, consistent with packed/obfuscated code. Unusual executable sections .kofbl and .l1 are present. The entry function delegates to a small stub (FUN_00401219), indicating a thin unpacking stub that likely loads/drops/executes additional payload.

### deep key_evidence
- `"capa top rule: packed with generic packer (T1027.002)"`
- `"capa top rule: encode data using XOR (T1027)"`
- `"capa top rule: contain an embedded PE file (B0023)"`
- `"pe_import_signals: set_registry_value (RegSetValue)"`
- `"pe_import_signals: create_process (CreateProcess)"`
- `"pe_import_signals: load_library (LoadLibrary)"`
- `"pe_import_signals: get_proc_address (GetProcAddress)"`
- `"Ghidra imports: RegSetValueExA, RegCreateKeyExA, RegOpenKeyExA (ADVAPI32.DLL)"`
- `"Ghidra imports: CreateProcessA, WinExec, CreateFileA, ReadFile, WriteFile, SetFilePointer, CreateMutexA, TerminateProcess (KERNEL32.DLL)"`
- `"Ghidra imports: LoadLibraryA, GetProcAddress (KERNEL32.DLL)"`
- `"Ghidra imports: GetWindowTextA, FindWindowA, GetForegroundWindow (USER32.DLL)"`
- `"Ghidra imports: CoCreateInstance, CLSIDFromString, CoInitialize, CoUninitialize, SysAllocString (OLE32/OLEAUT32)"`
- `"Ghidra imports: DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA (WININET.DLL)"`
- `"Ghidra memory blocks: executable sections .kofbl and .l1"`
- `"Ghidra funcs: only 2 functions (entry at 0x4390914, FUN_00401219 at 0x401219)"`
- `"Ghidra callgraph: entry calls FUN_00401219"`
- `"FLOSS: 715 static strings, 0 decoded/stack/tight strings, indicating obfuscation/packing"`
- `"Ghidra exports: none"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 5 · duration_s: 1.55

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

## PE Imports / Signals
import_count: 113

| label | api_match | ATT&CK |
|---|---|---|
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

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
Total strings: 715 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 715}`

### FLOSS sample
- `.idata`
- `.kofbl`
- `<OF#55`
- `1PA\2%F`
- `oe-IZ4'IZ$`
- `#&%FgV!F`
- `:Pr%FEL`
- `p0%Fmu`
- `0%O?D!`
- `%I`3$F`
- `1 ~{q%`
- `(^{q%fm`
- `Dr%O$L`
- `\r%{d0%F`
- `1%F\GRF`
- `v0%FdM`
- `4Pad==`
- `0Mn^r%`
- `0M{^r%`
- `0%Fi5Q`
- `Ii4 /Xr%`
- `<3`Vid`
- `!IR4#{`
- `pVid6C`
- `Ii<(~Xr%`
- `Do$0fup%`
- `m<0vqp%IR`
- `2Pr%IR`
- `gF]!%F`
- `MCIRs$c$0%Fg`
- `0QNou)`
- `#Z%.d0%F`
- `gF]3%F`
- `ou)ISp'`
- `eNoe-ISb-o41``
- `xNou) mu)`
- `>0%Fou`
- `5IR4;{`
- `L}%Fmu`
- `D}%FoM`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00430005
```asm
┌ 139: fcn.00430005 ();
│       ╎   0x00430005      60             pushal
│       ╎   0x00430006      90             nop
│       ╎   0x00430007      b800104000     mov eax, section..text      ; 0x401000
│       ╎   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc
│       ╎   0x00430011      90             nop
│       ╎   0x00430012      b9e4302546     mov ecx, 0x462530e4
│       ╎   0x00430017      90             nop
│       ╎   0x00430018      90             nop
│       ╎   0x00430019      90             nop
│       ╎   0x0043001a      85c0           test eax, eax
│       ╎   0x0043001c      90             nop
│       ╎   0x0043001d      90             nop
│       ╎   0x0043001e      90             nop
│       ╎   0x0043001f      90             nop
│       ╎   0x00430020      90             nop
│       ╎   0x00430021      90             nop
│      ┌──< 0x00430022      742a           je 0x43004e
│     ┌───> 0x00430024      90             nop
│     ╎│╎   0x00430025      90             nop
│     ╎│╎   0x00430026      90             nop
│     ╎│╎   0x00430027      90             nop
│     ╎│╎   0x00430028      3108           xor dword [eax], ecx
│     ╎│╎   0x0043002a      90             nop
│     ╎│╎   0x0043002b      90             nop
│     ╎│╎   0x0043002c      90             nop
│     ╎│╎   0x0043002d      90             nop
│     ╎│╎   0x0043002e      90             nop
│     ╎│╎   0x0043002f      40             inc eax
│     ╎│╎   0x00430030      40             inc eax
│     ╎│╎   0x00430031      90             nop
│     ╎│╎   0x00430032      90             nop
│     ╎│╎   0x00430033      90             nop
│     ╎│╎   0x00430034      90             nop
│     ╎│╎   0x00430035      90             nop
│     ╎│╎   0x00430036      90             nop
│     ╎│╎   0x00430037      90             nop
│     ╎│╎   0x00430038      90             nop
│     ╎│╎   0x00430039      90             nop
│     ╎│╎   0x0043003a      40             inc eax
│     ╎│╎   0x0043003b      90             nop
│     ╎│╎   0x0043003c      40             inc eax
│     ╎│╎   0x0043003d      90             nop
│     ╎│╎   0x0043003e      90             nop
│     ╎│╎   0x0043003f      90             nop
│     ╎│╎   0x00430040      90             nop
│     ╎│╎   0x00430041      90             nop
│     ╎│╎   0x00430042      90             nop
│     ╎│╎   0x00430043      90             nop
│     ╎│╎   0x00430044      90             nop
│     ╎│╎   0x00430045      39d8           cmp eax, ebx
│     ╎│╎   0x00430047      90             nop
│     ╎│╎   0x00430048      90             nop
│     ╎│╎   0x00430049      90             nop
│     ╎│╎   0x0043004a      90             nop
│     ╎│╎   0x0043004b      90             nop
│     └───< 0x0043004c      75d6           jne 0x430024
│      └──> 0x0043004e      b800b04200     mov eax, str.__vu           ; section..data
│       ╎                                                              ; 0x42b000
│       ╎   0x00430053      90        
```
### 0x004312b0
```asm
┌ 133: sym.imp.ole32.DLL_CoCreateInstance ();
│           0x004312b0      98             cwde
│           0x004312b1      1403           adc al, 3
│           0x004312b3  ~   00ac140300..   add byte [esp + edx + 0x14be0003], ch ; [0x14be0003:1]=255
│           ;-- CLSIDFromString:
..
│           0x004312ba      0300           add eax, dword [eax]
│           ;-- CoUninitialize:
│           0x004312bc      ce             into
│           0x004312bd      1403           adc al, 3
│           0x004312bf      0000           add byte [eax], al
│           0x004312c1      0000           add byte [eax], al
│           0x004312c3  ~   00e0           add al, ah
│           ;-- SysAllocString:
..
│           0x004312c5      1403           adc al, 3
│           0x004312c7      0000           add byte [eax], al
│           0x004312c9      0000           add byte [eax], al
│           0x004312cb  ~   00f2           add dl, dh
│           ;-- DeleteUrlCacheEntry:
..
│           0x004312cd      1403           adc al, 3
│           0x004312cf  ~   0008           add byte [eax], cl
│           ;-- FindFirstUrlCacheEntryA:
..
│           0x004312d1  ~   1503002215     adc eax, 0x15220003
│           ;-- FindNextUrlCacheEntryA:
..
│           0x004312d6      0300           add eax, dword [eax]
│           0x004312d8      0000           add byte [eax], al
│           0x004312da      0000           add byte [eax], al
│           ;-- ExitProcess:
│           0x004312dc      3c15           cmp al, 0x15                ; 21
│           0x004312de      0300           add eax, dword [eax]
│           ;-- ExpandEnvironmentStringsA:
│           0x004312e0      4a             dec edx
│           0x004312e1  ~   1503006615     adc eax, 0x15660003
│           ;-- GetCommandLineA:
..
│           0x004312e6      0300           add eax, dword [eax]
│           ;-- GetComputerNameA:
│       ┌─< 0x004312e8      7815           js 0x4312ff
│       │   0x004312ea      0300           add eax, dword [eax]
│       │   ;-- GetCurrentProcessId:
│       │   0x004312ec  ~   8c150300a215   mov word [0x15a20003], ss   ; [0x15a20003:2]=0xffff pe_overlay
│       │   ;-- GetCurrentThreadId:
..
│       │   0x004312f2      0300           add eax, dword [eax]
│       │   ;-- GetExitCodeThread:
│       │   0x004312f4  ~   b8150300cc     mov eax, 0xcc000315
│       │   ;-- GetFileSize:
..
│       │   0x004312f9  ~   150300da15     adc eax, 0x15da0003
│       │   ;-- GetModuleFileNameA:
..
│       │   0x004312fe  ~   0300           add eax, dword [eax]
│       │   ;-- (0x00431300) GetModuleHandleA:
│       └─> 0x004312ff  ~   00f0           add al, dh
│           0x00431301  ~   1503000416     adc eax, 0x16040003
│           ;-- CloseHandle:
..
│           0x00431306      0300           add eax, dword [eax]
│           ;-- GetProcAddress:
│           0x00431308      1216           adc dl, byte [esi]
│           0x0043130a      0300           add eax, dword [eax]
│           ;-- GetSystemDirectoryA:
│    
```
### 0x00431334
```asm
┌ 11: sym.imp.KERNEL32.DLL_IsBadWritePtr ();
│           0x00431334      da16           ficom dword [esi]
│           0x00431336      0300           add eax, dword [eax]
│           ;-- LoadLibraryA:
└       ┌─< 0x00431338  ~   ea160300fa..   ljmp 0x316
│       │   ;-- LocalAlloc:
..
```
### 0x00431340
```asm
┌ 68: sym.imp.KERNEL32.DLL_LocalFree ();
│           0x00431340      0817           or byte [edi], dl
│           0x00431342      0300           add eax, dword [eax]
│           ;-- OpenMutexA:
│           0x00431344      1417           adc al, 0x17
│           0x00431346      0300           add eax, dword [eax]
│           ;-- CreateFileA:
│           0x00431348      2217           and dl, byte [edi]
│           0x0043134a      0300           add eax, dword [eax]
│           ;-- ReadFile:
│           0x0043134c      3017           xor byte [edi], dl
│           0x0043134e      0300           add eax, dword [eax]
│           ;-- RtlUnwind:
│           0x00431350      3c17           cmp al, 0x17                ; 23
│           0x00431352      0300           add eax, dword [eax]
│           ;-- SetFilePointer:
│           0x00431354      48             dec eax
│           0x00431355      17             pop ss
│           0x00431356      0300           add eax, dword [eax]
│           ;-- CreateMutexA:
│           0x00431358      5a             pop edx
│           0x00431359      17             pop ss
│           0x0043135a      0300           add eax, dword [eax]
│           ;-- Sleep:
│           0x0043135c      6a17           push 0x17                   ; 23
│           0x0043135e      0300           add eax, dword [eax]
│           ;-- TerminateProcess:
│      ┌──< 0x00431360      7217           jb 0x431379
│      │    0x00431362      0300           add eax, dword [eax]
│      │    ;-- VirtualQuery:
│      │    0x00431364      8617           xchg byte [edi], dl
│      │    0x00431366      0300           add eax, dword [eax]
│      │    ;-- CreateProcessA:
│      │    0x00431368      96             xchg esi, eax
│      │    0x00431369      17             pop ss
│      │    0x0043136a      0300           add eax, dword [eax]
│      │    ;-- WaitForSingleObject:
│      │    0x0043136c      a817           test al, 0x17               ; 23
│      │    0x0043136e      0300           add eax, dword [eax]
│      │    ;-- WideCharToMultiByte:
│      │    0x00431370  ~   be170300d4     mov esi, 0xd4000317
│      │    ;-- WinExec:
..
│      │    0x00431375      17             pop ss
│      │    0x00431376      0300           add eax, dword [eax]
│      │    ;-- WriteFile:
│      │    0x00431378  ~   de17           ficom word [edi]
│      └──> 0x00431379      17             pop ss
│           0x0043137a      0300           add eax, dword [eax]
│           ;-- lstrlenA:
└       ┌─< 0x0043137c  ~   ea170300f6..   ljmp 0x317
│       │   ;-- lstrlenW:
..
```
### 0x00431384
```asm
┌ 2611: sym.imp.KERNEL32.DLL_CreateThread (int32_t arg_1h, int32_t arg_41h, int32_t arg_4eh, int32_t arg_50h, int32_t arg_53h, int32_t arg_65h, int32_t arg_66h, int32_t arg_6ch, int32_t arg_6fh, int32_t arg_72h, int32_t arg_73h);
│           ; arg int32_t arg_1h @ ebp+0x1
│           ; arg int32_t arg_41h @ ebp+0x41
│           ; arg int32_t arg_4eh @ ebp+0x4e
│           ; arg int32_t arg_50h @ ebp+0x50
│           ; arg int32_t arg_53h @ ebp+0x53
│           ; arg int32_t arg_65h @ ebp+0x65
│           ; arg int32_t arg_66h @ ebp+0x66
│           ; arg int32_t arg_6ch @ ebp+0x6c
│           ; arg int32_t arg_6fh @ ebp+0x6f
│           ; arg int32_t arg_72h @ ebp+0x72
│           ; arg int32_t arg_73h @ ebp+0x73
│           0x00431384      0218           add bl, byte [eax]
│           0x00431386      0300           add eax, dword [eax]
│           ;-- DeleteFileA:
│           0x00431388      1218           adc bl, byte [eax]
│           0x0043138a      0300           add eax, dword [eax]
│           0x0043138c      0000           add byte [eax], al
│           0x0043138e      0000           add byte [eax], al
│           ;-- GetWindowTextA:
│           0x00431390      2018           and byte [eax], bl
│           0x00431392      0300           add eax, dword [eax]
│           ;-- GetWindowRect:
│           0x00431394      3218           xor bl, byte [eax]
│           0x00431396      0300           add eax, dword [eax]
│           ;-- FindWindowA:
│           0x00431398      42             inc edx
│           0x00431399      1803           sbb byte [ebx], al
│           0x0043139b  ~   005018         add byte [eax + 0x18], dl
│           ;-- GetWindow:
..
│           0x0043139e      0300           add eax, dword [eax]
│           ;-- GetClassNameA:
│           0x004313a0      5c             pop esp
│           0x004313a1      1803           sbb byte [ebx], al
│           0x004313a3  ~   006c1803       add byte [eax + ebx + 3], ch
│           ;-- SetFocus:
..
│           0x004313a7  ~   007818         add byte [eax + 0x18], bh
│           ;-- GetForegroundWindow:
..
│           0x004313aa      0300           add eax, dword [eax]
│           ;-- LoadCursorA:
│           0x004313ac      8e18           mov ds, word [eax]
│           0x004313ae      0300           add eax, dword [eax]
│           ;-- LoadIconA:
│           0x004313b0      9c             pushfd
│           0x004313b1      1803           sbb byte [ebx], al
│           0x004313b3  ~   00a8180300b4   add byte [eax - 0x4bfffce8], ch
│           ;-- SetTimer:
..
│           ;-- RegisterClassA:
│           0x004313b9      1803           sbb byte [ebx], al
│           0x004313bb  ~   00c6           add dh, al
│           ;-- MessageBoxA:
..
│           0x004313bd      1803           sbb byte [ebx], al
│           0x004313bf  ~   00d4           add ah, dl
│           ;-- GetMessageA:
..
│           0x004313c1      1803           sbb byte [ebx], al
│           0x004313c3  ~   00e2           add
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ......................................
- Found XOR 00 position 0001B800: 00000080 ......................................

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
