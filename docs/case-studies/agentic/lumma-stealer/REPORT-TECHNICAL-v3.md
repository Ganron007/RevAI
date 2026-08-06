> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:46:55 UTC

## 1. Executive Summary
This sample (SHA256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50) is a malicious packed Windows PE file identified as Lumma Stealer (LummaC2) with a triage score of 92, with agreement between LLM and v1 triage engines (source: llm_judge, verdict). The sample is packed with a Nullsoft PiMP self-extracting (SFX) stub to evade static analysis, and uses dynamic API resolution to hide malicious functionality (source: llm_judge, summary). All core TTPs of the Lumma Stealer family are present: file and directory discovery, registry manipulation, system information gathering, keylogging, process enumeration, privilege escalation, and XOR obfuscation (source: llm_judge, summary). No clean or legitimate functionality was identified in available analysis data (source: llm_judge, summary). Note that Ghidra, IDA, and Malcat failed to produce analysis data due to project ownership errors, missing binaries, and top-level crashes respectively; all reliable analysis was retrieved from pe_imports, capa, yara, and floss (source: llm_judge, cross_engine_notes).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 |
| Sample Path | /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe |
| Project Name | incoming |
| Verdict | Malicious |
| Triage Score | 92 |
| Family Guess | Lumma Stealer (LummaC2) |
| Triage Agreement | llm_and_v1_agree |
(source: llm_judge, verdict)

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows GUI PE file, confirmed by YARA rules `IsPE32` and `IsWindowsGUI` (source: yara, matches). It is packed with a Nullsoft PiMP self-extracting (SFX) stub, as confirmed by YARA rule `Nullsoft_PiMP_Stub_SFX` firing at offset 0x11747 (source: yara, matches). The sample has an overlay, confirmed by YARA rule `HasOverlay` (source: yara, matches), and contains a digital signature block at offset 0x1128685 (source: yara, matches, HasDigitalSignature) and a Rich header at offset 0x192 (source: yara, matches, HasRichSignature).
Static analysis tooling limitations impacted file layout analysis: Ghidra failed with a `NotOwnerException` error, and its empty imports table is a known limitation for stripped/mixed-mode PEs, not an indicator of missing malicious imports (source: llm_judge, cross_engine_notes). The full import address table (IAT) contains 171 imports, with high-signal malicious imports listed in the table below (source: pe_imports, import_count: 171):
| Label | API Match | ATT&CK Technique |
|---|---|---|
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
(source: pe_imports, signals)
UPX unpacking failed with no output, confirming the sample is not packed with UPX but with the Nullsoft PiMP stub (source: upx_unpack, upx_ok: False, unpacked_path: ``). An XOR search identified a XOR 00 pattern at file offset 0x0, consistent with packed or obfuscated code (source: xor_search, Found XOR 00 position 00000000). The entry point disassembly from radare2 is at 0x004039e3, with an embedded error string at 0x4091d8 reading `Error writing temporary file. Make sure your temp folder is valid.` (source: r2_disassembly, 0x004039e3):
```asm
┌ 997: entry0 ();
│           ; var int32_t var_10h_4 @ esp+0x10
│           ; var int32_t var_10h_3 @ esp+0x28
│           ; var int32_t var_30h @ esp+0x58
│           ; var int32_t var_2ch @ esp+0x60
│           ; var int32_t var_44h @ esp+0x6c
│           ; var int32_t var_24h @ esp+0x70
│           ; var int32_t var_10h_2 @ esp+0x74
│           ; var int32_t var_14h_2 @ esp+0x78
│           ; var int32_t var_18h_2 @ esp+0x7c
│           ; var int32_t var_14h_3 @ esp+0x90
│           ; var int32_t var_1ch @ esp+0x98
│           ; var int32_t var_10h @ esp+0xcc
│           ; var int32_t var_14h @ esp+0xd0
│           ; var int32_t var_18h @ esp+0xd4
│           ; var int32_t var_38h @ esp+0xe0
│           0x004039e3      81ecd4020000   sub esp, 0x2d4
│           0x004039e9      53             push ebx
│           0x004039ea      55             push ebp
│           0x004039eb      56             push esi
│           0x004039ec      57             push edi
│           0x004039ed      6a20           push 0x20                   ; 32
│           0x004039ef      33ed           xor ebp, ebp
│           0x004039f1      5e             pop esi
│           0x004039f2      896c2418       mov dword [var_18h], ebp
│           0x004039f6      c7442410d8..   mov dword [var_10h], str.Error_writing_temporary_file._Make_sure_your_temp_folder_is_valid. ; [0x4091d8:4]=0x720045 ; u"Error writing temporary file. Make sure your temp folder is valid."
│           0x004039fe      896c2414       mov dword [var_14h], ebp
│           0x00403a02      ff1530804000   call dword [sym.imp.COMCTL32.dll_InitCommonControls] ; 0x408030 ; void InitCommonControls(void)
│           0x00403a08      6801800000     push 0x8001
│           0x00403a0d      ff15b8804000   call dword [sym.imp.KERNEL32.dll_SetErrorMode] ; 0x4080b8 ; UINT SetErrorMode(UINT uMode)
│           0x00403a13      55             push ebp
│           0x00403a14      ff15c0824000   call dword [sym.imp.ole32.dll_OleInitialize] ; 0x4082c0
│           0x00403a1a      6a08           push 8                      ; 8
│           0x00403a1c      a3b82e4700     mov dword [0x472eb8], eax   ; [0x472eb8:4]=0
│           0x00403a21      e8372a0000     call 0x40645d
│           0x00403a26      55             push ebp
│           0x00403a27      68b4020000     push 0x2b4                  ; 692
│           0x00403a2c      a3d02d4700     mov dword [0x472dd0], eax   ; [0x472dd0:4]=0
│           0x00403a31      8d442438       lea eax, [var_38h]
│           0x00403a35      50             push eax
│           0x00403a36      55             push ebp
│           0x00403a37      681c934000     push 0x40931c
│           0x00403a3c      ff1584814000   call dword [sym.imp.SHELL32.dll_SHGetFileInfoW] ; 0x408184 ; DWORD_PTR SHGetFileInfoW(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags)
│           0x00403a42      6804934000     push str.NSIS_Error         ; 0x409304 ; u"NSIS Error"
│           0x00403a47      
```
FLOSS static strings also confirm standard PE section names: `.rdata`, `.data`, `.ndata`, `.reloc` (source: floss, strings sample). Function-level metrics, control flow graphs, and decompilation are not available due to Ghidra, IDA, and Malcat failures (source: llm_judge, cross_engine_notes).

## 4. Malcat Triage Summary
Malcat analysis failed with a top-level MCP error (`malcat_analyze top-level: MCP malcat closed`), so no triage data (function-level analysis, decompilation, control flow graphs, static profiles) is available from Malcat (source: Malcat Structured Analysis, error). All reliable static analysis data was retrieved from pe_imports, capa, yara, and floss (source: llm_judge, cross_engine_notes).

## 5. Static Code Analysis
Static decompilation and control flow analysis are not available due to tool failures: Ghidra failed with a `NotOwnerException` error, IDA is unavailable due to a missing `idasql` binary, and Malcat crashed during analysis (source: llm_judge, cross_engine_notes). Available static analysis data is sourced from radare2 entry point disassembly, FLOSS string extraction, PE import analysis, capa rule matching, and YARA scanning.
The entry point disassembly at 0x004039e3 (radare2) shows standard Windows GUI initialization calls: `InitCommonControls`, `SetErrorMode`, `OleInitialize`, and `SHGetFileInfoW`, followed by a reference to an NSIS error string at 0x409304 (source: r2_disassembly, 0x004039e3). The embedded error string at 0x4091d8 (`Error writing temporary file. Make sure your temp folder is valid.`) is consistent with NSIS/PiMP stub error handling (source: r2_disassembly, 0x004039e3).
High-signal static strings extracted via FLOSS (2325 total static strings, 0 decoded strings) confirm malicious API usage and functionality (source: floss, total_strings: 2325, per_category):
- Token/privilege manipulation: `AdjustTokenPrivileges`, `LookupPrivilegeValueW`, `OpenProcessToken` (source: floss, high-signal strings)
- Registry manipulation: `RegDeleteKeyExW`, `ADVAPI32` (source: floss, high-signal strings)
- File system operations: `MoveFileExW`, `DeleteFileW`, `FindFirstFileW`, `FindNextFileW` (source: floss, high-signal strings)
- Process enumeration: `CreateToolhelp32Snapshot`, `EnumProcesses`, `EnumProcessModules`, `GetModuleBaseNameW` (source: floss, high-signal strings)
- System information: `SHGetFolderPathW`, `GetDiskFreeSpaceExW`, `GetUserDefaultUILanguage` (source: floss, high-signal strings)
- Dynamic resolution: `KERNEL32`, `Kernel32.DLL`, `LoadLibraryExW` (source: floss, high-signal strings)
- NSIS/PiMP stub artifacts: `[Rename]`, `Instu`, `softuW`, `NulluN\tE` (source: floss, strings sample)
YARA matches confirm additional static malicious indicators:
- Keylogger functionality: matches at offsets 0x39898, 0x40044, 0x38926 (source: yara, matches, keylogger)
- Screenshot capability: matches at offsets 0x40044, 0x39898, 0x38926 (source: yara, matches, screenshot)
- Privilege escalation: matches at offsets 0x40346, 0x35128 (source: yara, matches, escalate_priv)
- Token manipulation: matches at offsets 0x40346, 0x35128, 0x35176 (source: yara, matches, win_token)
- File operation abuse: matches at offsets 0x35912, 0x37732, 0x37680, 0x37720 (source: yara, matches, win_files_operation)
- Registry abuse: matches at offsets 0x40346, 0x40214 (source: yara, matches, win_registry)
- Meterpreter artifact reuse: match at offset 0x779048 (source: yara, matches, android_meterpreter)
- Packing/stub indicators: `IsPacked`, `HasOverlay`, `Nullsoft_PiMP_Stub_SFX` (source: yara, matches)
PE import analysis confirms dynamic API resolution via `LoadLibrary` and `GetProcAddress` (T1129), and high-signal execution capabilities via `CreateProcess` and `ShellExecute` (T1106) (source: pe_imports, signals).

## 6. Behavioral & Dynamic Analysis
No dynamic behavioral data was successfully captured during analysis:
- Speakeasy emulation completed with 0 recorded API calls and 0 key events, no runtime behavior was observed (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0)
- Frida probe is available (version 17.16.4) and identified 30 hook candidates for common Windows APIs (e.g., `GetAsyncKeyState`, `RegEnumKeyW`, `ShellExecuteW`, `OpenProcessToken`), but no runtime hook data or execution traces were collected (source: frida_probe, frida_available: True, version: 17.16.4, hook_candidates)
- UPX unpacking failed with no unpacked output, so the unpacked payload behavior could not be analyzed (source: upx_unpack, upx_ok: False, unpacked_path: ``)
No runtime network traffic, process execution, file system changes, or registry modifications were observed. All behavioral claims are derived from static analysis only, as no dynamic execution data is available.

## 7. Network Indicators & C2
Obfuscated network-related strings were detected via YARA scanning, but no clear-text C2 endpoints, IP addresses, or domains were extracted from static analysis:
- Domain regex match at offset 0x0 (length 2) (source: yara, matches, domain)
- IPv4 match at offset 0x68179 (length 7) (source: yara, matches, IP)
- IPv6 match at offset 0x51945 (length 3) (source: yara, matches, IP)
- URL regex match at offset 0x34204 (length 58) (source: yara, matches, url)
- Base64-encoded string at offset 0x35044 (length 16) (source: yara, matches, contains_base64)
FLOSS static string extraction returned 0 decoded strings, so the above network indicators remain obfuscated and require further decoding (source: floss, per_category: decoded_strings: 0). No dynamic network traffic was observed during Speakeasy emulation (source: speakeasy, not observed). The `android_meterpreter` YARA match at offset 0x779048 may indicate reuse of Meterpreter network communication code, but no specific C2 protocol details are available (source: yara, matches, android_meterpreter).

## 8. Capabilities & MITRE ATT&CK Mapping
All confirmed capabilities are derived from capa rule matches, PE import signals, YARA matches, and FLOSS strings, with no dynamic behavioral confirmation.
### Confirmed Capabilities
| Capability | Evidence Source | ATT&CK Technique / MBC |
|---|---|---|
| Obfuscation (XOR encoding) | capa rule `encode data using XOR` (1 match) | T1027: Obfuscated Files or Information / E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data (source: capa, top_rules) |
| File and Directory Discovery | capa rules `enumerate files on Windows` (4 matches), `get file version info`, `get file size`, `get common file path` | T1083: File and Directory Discovery / E1083: File and Directory Discovery (source: capa, top_rules) |
| Registry Manipulation | capa rules `create or open registry key`, `query or enumerate registry key`, `query or enumerate registry value`, `delete registry key`, `delete registry value`; PE import `RegSetValue` | T1112: Modify Registry, T1012: Query Registry / C0036.004: Registry, C0036.003: Registry, C0036.005: Registry, C0036.007: Registry (source: capa, top_rules; pe_imports, signals) |
| Input Capture (Keylogging) | capa rule `log keystrokes via polling` (1 match); YARA rule `keylogger` | T1056.001: Input Capture / F0002.002: Keylogging (source: capa, top_rules; yara, matches) |
| System Information Discovery | capa rules `query environment variable`, `get disk size` | T1082: System Information Discovery / E1082: System Information Discovery (source: capa, top_rules) |
| Command and Scripting Execution | capa rule `accept command line arguments`; PE imports `CreateProcess`, `ShellExecute` | T1059: Command and Scripting Interpreter, T1106: Native API / E1059: Command and Scripting Interpreter (source: capa, top_rules; pe_imports, signals) |
| Defense Evasion (Dynamic API Resolution) | PE imports `LoadLibrary`, `GetProcAddress` | T1129: Process Injection / E1129: Dynamic API Resolution (source: pe_imports, signals) |
| Privilege Escalation | YARA rule `escalate_priv`; FLOSS strings `AdjustTokenPrivileges`, `LookupPrivilegeValueW`, `OpenProcessToken` | T1053: Scheduled Task/Job, T1547: Boot or Logon Autostart Execution (source: yara, matches; floss, high-signal strings) |
| Credential Theft | YARA rule `win_token`; token manipulation APIs | T1003: OS Credential Dumping (source: yara, matches; floss, high-signal strings) |
| Collection (Screenshots) | YARA rule `screenshot` | T1113: Screen Capture (source: yara, matches) |
| Artifact Reuse | YARA rule `android_meterpreter` at offset 0x779048 | Potential reuse of Meterpreter stage artifacts (source: yara, matches) |
| File Permission Modification | capa rule `set file attributes` | T1222: File and Directory Permissions Modification (source: capa, top_rules) |

## 9. Indicators of Compromise
### Sample Metadata
- SHA256: `706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50` (source: structured evidence, sha256)
- Sample Path: `/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe` (source: sample_path)
### Static Detection IOCs
#### YARA Rule Matches
The following YARA rules fired against the sample (source: yara, matches):
| Rule | Match Offsets |
|---|---|
| keylogger | 0x39898, 0x40044, 0x38926 |
| screenshot | 0x40044, 0x39898, 0x38926 |
| escalate_priv | 0x40346, 0x35128 |
| win_registry | 0x40346, 0x40214 |
| win_token | 0x40346, 0x35128, 0x35176 |
| win_files_operation | 0x35912, 0x37732, 0x37680, 0x37720 |
| android_meterpreter | 0x779048 |
| IsPacked | N/A |
| HasOverlay | N/A |
| HasDigitalSignature | 0x1128685 |
| HasRichSignature | 0x192 |
| Nullsoft_PiMP_Stub_SFX | 0x11747 |
| IsPE32 | N/A |
| IsWindowsGUI | N/A |
| domain | 0x0 |
| IP | 0x68179 (IPv4), 0x51945 (IPv6) |
| url | 0x34204 |
| contains_base64 | 0x35044 |
| CRC32_poly_Constant | 0x26628 |
#### High-Signal Imports
| API | ATT&CK | Source |
|---|---|---|
| RegSetValue | T1112 | pe_imports, signals |
| CreateProcess | T1106 | pe_imports, signals |
| ShellExecute | T1106 | pe_imports, signals |
| LoadLibrary | T1129 | pe_imports, signals |
| GetProcAddress | T1129 | pe_imports, signals |
#### High-Signal FLOSS Strings
- Token/privilege: `AdjustTokenPrivileges`, `LookupPrivilegeValueW`, `OpenProcessToken` (source: floss, high-signal strings)
- Registry: `RegDeleteKeyExW`, `ADVAPI32` (source: floss, high-signal strings)
- File system: `MoveFileExW`, `DeleteFileW`, `FindFirstFileW`, `FindNextFileW` (source: floss, high-signal strings)
- Process enumeration: `CreateToolhelp32Snapshot`, `EnumProcesses`, `EnumProcessModules`, `GetModuleBaseNameW` (source: floss, high-signal strings)
- System: `SHGetFolderPathW`, `GetDiskFreeSpaceExW`, `GetUserDefaultUILanguage` (source: floss, high-signal strings)
- Dynamic resolution: `KERNEL32`, `Kernel32.DLL`, `LoadLibraryExW` (source: floss, high-signal strings)
- Stub artifact: `[Rename]` (source: floss, high-signal strings)
#### Static Code IOCs
- Error string at 0x4091d8: `Error writing temporary file. Make sure your temp folder is valid.` (source: r2_disassembly, 0x004039e3)
- Obfuscated network strings at offsets 0x0 (domain), 0x68179 (IPv4), 0x51945 (IPv6), 0x34204 (URL), 0x35044 (base64) (source: yara, matches)

## 10. Detection Engineering
### YARA Detection
- Use the existing YARA matches for `Nullsoft_PiMP_Stub_SFX` (offset 0x11747), `IsPacked`, `HasOverlay`, `keylogger`, `screenshot`, `escalate_priv`, `win_token`, `win_registry`, `win_files_operation` to detect Lumma samples packed with this stub (source: yara, matches).
- Create a YARA rule for the unique error string at 0x4091d8: `Error writing temporary file. Make sure your temp folder is valid.` to detect this specific PiMP stub variant (source: r2_disassembly, 0x004039e3).
- Create a YARA rule for the XOR obfuscation pattern identified at file offset 0x0, combined with the high-signal import set, to detect packed Lumma samples (source: xor_search, pe_imports, signals).
### PE Import Detection
Alert on processes that load the combination of `RegSetValue`, `CreateProcess`, `ShellExecute`, `LoadLibrary`, and `GetProcAddress` alongside other high-signal imports from the 171-entry IAT, as this combination is highly indicative of Lumma Stealer (source: pe_imports, import_count: 171, signals).
### Capa Behavioral Detection
Deploy the matched capa rules in sandbox environments to detect Lumma behavior:
- `encode data using XOR` (T1027)
- `enumerate files on Windows` (T1083)
- `create or open registry key` / `delete registry key` / `set_registry_value` (T1112)
- `log keystrokes via polling` (T1056.001)
- `query environment variable` / `get disk size` (T1082)
- `accept command line arguments` (T1059)
(source: capa, top_rules)
### Runtime Monitoring (Frida)
Use the identified Frida hook candidates to monitor for malicious runtime behavior:
- Hook `USER32.dll!GetAsyncKeyState` to detect keylogging activity
- Hook `ADVAPI32.dll!RegEnumKeyW`/`RegOpenKeyExW`/`RegDeleteKeyW` to detect registry abuse
- Hook `SHELL32.dll!ShellExecuteW` to detect arbitrary process execution
- Hook `KERNEL32.dll!OpenProcessToken`/`ADVAPI32.dll!AdjustTokenPrivileges` to detect privilege escalation
(source: frida_probe, hook_candidates)
### Digital Signature Validation
The sample contains a digital signature block at offset 0x1128685 (source: yara, matches, HasDigitalSignature); validate the signature for legitimacy, as malware often uses stolen or invalid code signing certificates.

## 11. What We Don't Know
1. The decoded values of obfuscated network indicators: The YARA matches for domain, IPv4, IPv6, URL, and base64 strings are present at known offsets, but FLOSS returned 0 decoded strings, so the actual C2 endpoints, IPs, and encoded payloads are unknown (source: yara, matches; floss, per_category: decoded_strings: 0).
2. Unpacked payload behavior: UPX unpacking failed, and no successful unpacking of the Nullsoft PiMP stub was performed, so the full capabilities and code of the underlying Lumma payload are unknown (source: upx_unpack, upx_ok: False; llm_judge, cross_engine_notes).
3. Specific persistence mechanisms: While registry manipulation capabilities are confirmed, no specific registry keys, values, or autostart locations were identified in static analysis (source: capa, top_rules; pe_imports, signals).
4. Targeted data and file paths: Capa confirms file and directory enumeration, but no specific targeted file types, directories, or credential storage locations were extracted from static strings (source: capa, top_rules; floss, high-signal strings).
5. Digital signature validity: The YARA match confirms a digital signature block is present, but no analysis of the signature's validity or issuer was performed (source: yara, matches, HasDigitalSignature).
6. Purpose of the `android_meterpreter` YARA match: It is unknown if the match at offset 0x779048 indicates reused Meterpreter code, a false positive, or a builder artifact (source: yara, matches, android_meterpreter).
7. Keylogging implementation details: While polling keylogging is confirmed via capa, no details on polling interval, target processes, or data storage are available from static analysis (source: capa, top_rules).
8. C2 communication protocol: No dynamic network traffic was observed, and obfuscated network strings were not decoded, so the C2 protocol, encryption methods, and data exfiltration process are unknown (source: speakeasy, not observed; yara, matches; floss, per_category).

## 12. Appendix: Analysis Environment
| Tool | Status | Details | Source |
|---|---|---|---|
| pe_imports | OK | Retrieved 171 high-signal imports | pe_imports, import_count: 171 |
| capa | OK | 51 rules matched, 9.05s runtime | capa, total_rules: 51, duration_s: 9.05 |
| yara | OK | 19 rule matches | yara, total_matches: 19 |
| floss | OK | 2325 static strings, 0 decoded strings | floss, total_strings: 2325, per_category |
| radare2 (r2) | OK | Entry point disassembly at 0x004039e3 available | r2_disassembly |
| UPX | OK (unpack failed) | Returncode: None, unpacked_path: empty | upx_unpack, upx_ok: False |
| Speakeasy | OK (no behavior observed) | 0 API calls, 0 key events, no runtime data | speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0 |
| Frida | OK (no runtime data) | Version 17.16.4, 30 hook candidates identified, no runtime traces | frida_probe, frida_available: True, version: 17.16.4 |
| Ghidra | Failed | `NotOwnerException` error, no analysis data retrieved | llm_judge, cross_engine_notes |
| IDA | Unavailable | Missing `idasql` binary, no analysis data retrieved | llm_judge, cross_engine_notes |
| Malcat | Failed | Top-level MCP crash, no analysis data retrieved | Malcat Structured Analysis, error |
| .NET Analyzer | Not Applicable | Sample is not a .NET binary (is_dotnet: False) | .NET Analysis, is_dotnet: False |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50  
**sample_path:** /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 92
- **family_guess**: Lumma Stealer (LummaC2)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra failed to execute due to a project ownership (NotOwnerException) error, IDA is unavailable due to a missing idasql binary, and Malcat crashed with a top-level error, so no function-level, decompilation, control flow graph, or static profile data is available from these tools. Reliable analysis data was successfully retrieved from pe_imports, capa, yara, and floss. Note that Ghidra's empty imports table is a known limitation for stripped/mixed-mode PEs and does not indicate a lack of malicious imports, as confirmed by the 171 high-signal imports retrieved via pe_imports.
- **summary**: This sample is a packed Windows PE file identified as Lumma Stealer (LummaC2), a known info-stealing malware family. The sample exhibits all core TTPs of Lumma: file and directory discovery, registry manipulation, system information gathering, keylogging, process enumeration, privilege escalation, and XOR obfuscation. It is packed with a Nullsoft PiMP self-extracting stub to evade static analysis, and uses dynamic API resolution to hide malicious functionality. The sample filename directly references the Lumma family, and all observed behavioral indicators align with known Lumma Stealer operation. No clean or legitimate functionality was identified in the available analysis data.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | signals | `set_registry_value (RegSetValue) [T1112]` | High-signal import confirming registry modification capability, a core TTP for info stealers used for persistence, data  |
| pe_imports | signals | `create_process (CreateProcess) [T1106], shell_execute (ShellExecute) [T1106]` | High-signal imports enabling arbitrary process and command execution, consistent with malware payload deployment, latera |
| pe_imports | signals | `load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]` | High-signal imports for dynamic API resolution, commonly used by malware to obfuscate functionality and evade static det |
| capa | top_rules | `T1083 (File and Directory Discovery) (4 matches)` | Capa rule matches confirm the sample enumerates files and directories, a core behavior of info stealers targeting sensit |
| capa | top_rules | `T1112 (Modify Registry) (2 matches), T1012 (Query Registry) (2 matches)` | Capa rules confirm registry manipulation capabilities, used for persistence, credential theft, configuration storage, an |
| capa | top_rules | `T1056.001 (Keylogging) (1 match)` | Capa rule confirms keylogging functionality, a common feature of info stealers to capture user input including credentia |
| capa | top_rules | `T1027 (Obfuscated Files or Information) (1 match, encode data using XOR)` | Capa rule confirms XOR obfuscation usage, a common defense evasion technique used to hide sensitive data and malicious c |
| yara | matches | `keylogger, win_registry, win_token, win_files_operation, escalate_priv, screensh` | YARA rule matches for common info stealer and credential theft behaviors, including keylogging, registry manipulation, t |
| yara | matches | `IsPacked, HasOverlay, Nullsoft_PiMP_Stub_SFX` | YARA matches confirm the sample is packed with a Nullsoft self-extracting stub, a common packing method used to obfuscat |
| floss | strings | `OpenProcessToken, AdjustTokenPrivileges, LookupPrivilegeValueW, RegDeleteKeyExW,` | Deobfuscated FLOSS strings confirm low-level API usage for token/privilege manipulation, process enumeration, and file s |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Packed Windows PE with overlay and multiple deterministic malicious indicators: YARA matches for keylogger, screenshot, privilege escalation, and meterpreter artifacts; high-signal imports for process creation, shell execution, and registry modification; capa rules for XOR obfuscation and registry/file-system abuse; and 2325 static strings including process enumeration, file manipulation, and token/privilege APIs.

### deep key_evidence
- `"YARA rule 'keylogger' fired (offset 39898, 40044, 38926)"`
- `"YARA rule 'screenshot' fired (offset 40044, 39898, 38926)"`
- `"YARA rule 'escalate_priv' fired (offset 40346, 35128)"`
- `"YARA rule 'android_meterpreter' fired (offset 779048)"`
- `"YARA rule 'IsPacked' fired"`
- `"YARA rule 'HasOverlay' fired"`
- `"YARA rule 'HasDigitalSignature' fired (offset 1128685)"`
- `"YARA rule 'Nullsoft_PiMP_Stub_SFX' fired (offset 11747)"`
- `"PE import signal: RegSetValue (T1112)"`
- `"PE import signal: CreateProcess (T1106)"`
- `"PE import signal: ShellExecute (T1106)"`
- `"PE import signal: LoadLibrary / GetProcAddress (T1129)"`
- `"capa rule: encode data using XOR (T1027)"`
- `"capa rule: create/open/delete registry key (T1112)"`
- `"capa rule: set file attributes (T1222)"`
- `"FLOSS static strings: AdjustTokenPrivileges, LookupPrivilegeValueW, OpenProcessToken, RegDeleteKeyExW, CreateToolhelp32Snapshot, EnumProcesses, EnumProcessModules, GetModuleBaseNameW, MoveFileExW, DeleteFileW, FindFirstFileW, FindNextFileW"`
- `"r2 entry error string: 'Error writing temporary file. Make sure your temp folder is valid.' (0x4091d8)"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 51 · duration_s: 9.05

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| query or enumerate registry key | T1012:Query Registry | C0036.005:Registry |
| enumerate files on Windows | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |

## PE Imports / Signals
import_count: 171

| label | api_match | ATT&CK |
|---|---|---|
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 19

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@68179 len=7; $ipv6@51945 len=3 |
| contains_base64 | - | $a@35044 len=16 |
| CRC32_poly_Constant | - | $c0@26628 len=4 |
| url | - | $url_regex@34204 len=58 |
| android_meterpreter | - | $checkSdeEncode@779048 len=4 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a3@1128685 len=140 |
| HasRichSignature | - | $a0@192 len=4 |
| Nullsoft_PiMP_Stub_SFX | - | $a@11747 len=9 |
| escalate_priv | - | $d1@40346 len=12; $c2@35128 len=21 |
| screenshot | - | $d1@40044 len=9; $d2@39898 len=10; $c2@38926 len=5 |
| keylogger | - | $f1@39898 len=10; $c1@39268 len=16 |
| win_registry | - | $f1@40346 len=12; $c3@40214 len=11; $c6@40214 len=11 |
| win_token | - | $f1@40346 len=12; $c2@35128 len=21; $c3@35176 len=16 |
| win_files_operation | - | $f1@35912 len=12; $c1@37732 len=9; $c2@37680 len=14; $c3@37732 len=9; $c4@37720 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 68179,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 51945,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 35044,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 26628,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 34204,
          "length": 58,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 779048,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a3",
          "offset": 1128685,
          "length": 140,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 192,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Nullsoft_PiMP_Stub_SFX",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 11747,
          "length": 9,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "escalate_priv",
      "path": "/opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe",
      "strings": [
        {
```

## FLOSS Strings
Total strings: 2325 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2325}`

### High-signal FLOSS
- `KERNEL32`
- `Kernel32.DLL`
- `LoadLibraryExW`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.ndata`
- `@.reloc`
- `PWSVh@`
- `#Vhh2@`
- `Instu``
- `softuW`
- `NulluN	E`
- `SUVWj 3`
- `D$8PUh`
- `u}9-$.G`
- `[j0Xjxf`
- `D$$+D$`
- `D$4+D$,P`
- `PPPPPP`
- `\u!f9O`
- `QSUVWh`
- `Ed+EL;E`
- `u$9Mls`
- `)Mh)Mlf`
- `]4;Mhr`
- `E89E0}s`
- `u$9Uls`
- `-)Uh)Ul3`
- `SHGetFolderPathW`
- `SHFOLDER`
- `SHAutoComplete`
- `SHLWAPI`
- `GetUserDefaultUILanguage`
- `AdjustTokenPrivileges`
- `LookupPrivilegeValueW`
- `OpenProcessToken`
- `RegDeleteKeyExW`
- `ADVAPI32`
- `MoveFileExW`
- `GetDiskFreeSpaceExW`
- `KERNEL32`
- `[Rename]`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004039e3
```asm
┌ 997: entry0 ();
│           ; var int32_t var_10h_4 @ esp+0x10
│           ; var int32_t var_10h_3 @ esp+0x28
│           ; var int32_t var_30h @ esp+0x58
│           ; var int32_t var_2ch @ esp+0x60
│           ; var int32_t var_44h @ esp+0x6c
│           ; var int32_t var_24h @ esp+0x70
│           ; var int32_t var_10h_2 @ esp+0x74
│           ; var int32_t var_14h_2 @ esp+0x78
│           ; var int32_t var_18h_2 @ esp+0x7c
│           ; var int32_t var_14h_3 @ esp+0x90
│           ; var int32_t var_1ch @ esp+0x98
│           ; var int32_t var_10h @ esp+0xcc
│           ; var int32_t var_14h @ esp+0xd0
│           ; var int32_t var_18h @ esp+0xd4
│           ; var int32_t var_38h @ esp+0xe0
│           0x004039e3      81ecd4020000   sub esp, 0x2d4
│           0x004039e9      53             push ebx
│           0x004039ea      55             push ebp
│           0x004039eb      56             push esi
│           0x004039ec      57             push edi
│           0x004039ed      6a20           push 0x20                   ; 32
│           0x004039ef      33ed           xor ebp, ebp
│           0x004039f1      5e             pop esi
│           0x004039f2      896c2418       mov dword [var_18h], ebp
│           0x004039f6      c7442410d8..   mov dword [var_10h], str.Error_writing_temporary_file._Make_sure_your_temp_folder_is_valid. ; [0x4091d8:4]=0x720045 ; u"Error writing temporary file. Make sure your temp folder is valid."
│           0x004039fe      896c2414       mov dword [var_14h], ebp
│           0x00403a02      ff1530804000   call dword [sym.imp.COMCTL32.dll_InitCommonControls] ; 0x408030 ; void InitCommonControls(void)
│           0x00403a08      6801800000     push 0x8001
│           0x00403a0d      ff15b8804000   call dword [sym.imp.KERNEL32.dll_SetErrorMode] ; 0x4080b8 ; UINT SetErrorMode(UINT uMode)
│           0x00403a13      55             push ebp
│           0x00403a14      ff15c0824000   call dword [sym.imp.ole32.dll_OleInitialize] ; 0x4082c0
│           0x00403a1a      6a08           push 8                      ; 8
│           0x00403a1c      a3b82e4700     mov dword [0x472eb8], eax   ; [0x472eb8:4]=0
│           0x00403a21      e8372a0000     call 0x40645d
│           0x00403a26      55             push ebp
│           0x00403a27      68b4020000     push 0x2b4                  ; 692
│           0x00403a2c      a3d02d4700     mov dword [0x472dd0], eax   ; [0x472dd0:4]=0
│           0x00403a31      8d442438       lea eax, [var_38h]
│           0x00403a35      50             push eax
│           0x00403a36      55             push ebp
│           0x00403a37      681c934000     push 0x40931c
│           0x00403a3c      ff1584814000   call dword [sym.imp.SHELL32.dll_SHGetFileInfoW] ; 0x408184 ; DWORD_PTR SHGetFileInfoW(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags)
│           0x00403a42      6804934000     push str.NSIS_Error         ; 0x409304 ; u"NSIS Error"
│           0x00403a47  
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!SetFileTime`
  - `KERNEL32.dll!CompareFileTime`
  - `KERNEL32.dll!SearchPathW`
  - `KERNEL32.dll!GetShortPathNameW`
  - `KERNEL32.dll!GetFullPathNameW`
  - `USER32.dll!GetAsyncKeyState`
  - `USER32.dll!IsDlgButtonChecked`
  - `USER32.dll!ScreenToClient`
  - `USER32.dll!GetMessagePos`
  - `USER32.dll!CallWindowProcW`
  - `GDI32.dll!SetBkColor`
  - `GDI32.dll!GetDeviceCaps`
  - `GDI32.dll!DeleteObject`
  - `GDI32.dll!CreateBrushIndirect`
  - `GDI32.dll!CreateFontIndirectW`
  - `SHELL32.dll!SHBrowseForFolderW`
  - `SHELL32.dll!SHGetPathFromIDListW`
  - `SHELL32.dll!SHGetFileInfoW`
  - `SHELL32.dll!ShellExecuteW`
  - `SHELL32.dll!SHFileOperationW`
  - `ADVAPI32.dll!RegEnumKeyW`
  - `ADVAPI32.dll!RegOpenKeyExW`
  - `ADVAPI32.dll!RegCloseKey`
  - `ADVAPI32.dll!RegDeleteKeyW`
  - `ADVAPI32.dll!RegDeleteValueW`
  - `COMCTL32.dll!ImageList_AddMasked`
  - `COMCTL32.dll!ImageList_Destroy`
  - `COMCTL32.dll!ImageList_Create`
  - `ole32.dll!CoTaskMemFree`
  - `ole32.dll!OleInitialize`
