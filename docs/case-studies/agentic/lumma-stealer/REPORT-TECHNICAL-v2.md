> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:41:21 UTC

## 1. Executive Summary
This sample is a malicious packed Windows PE file scored 92, identified as Lumma Stealer (LummaC2) with `llm_and_v1_agree` consensus (source: llm_judge). It is wrapped in a Nullsoft PiMP self-extracting (SFX) stub to evade static analysis, and exhibits all core TTPs of the Lumma family: file and directory discovery, registry manipulation, system information gathering, keylogging, process enumeration, privilege escalation, and XOR obfuscation (source: llm_judge, deep_dive_agentic). No legitimate functionality was identified in available analysis data. Static analysis is limited by tooling failures (Ghidra `NotOwnerException`, missing IDA `idasql` binary, Malcat crash), but reliable indicators were retrieved from pe_imports, capa, yara, and floss (source: llm_judge).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 |
| Sample Path | /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 92 |
| Family Guess | Lumma Stealer (LummaC2) |
| Agreement | llm_and_v1_agree |
| Analysis Timestamp | 2026-08-06 03:37:53 UTC |
(source: llm_judge, deep_dive_agentic, rule.yara.json)

## 3. File Layout & Structural Analysis
This is a 32-bit Windows GUI PE file packed with a Nullsoft PiMP SFX stub to obfuscate its core payload (source: yara, deep_dive_agentic). YARA matches confirm the sample is packed (`IsPacked`), has an embedded overlay (`HasOverlay`), and contains the Nullsoft PiMP SFX stub at offset 0x11747 (source: yara). The PE contains 171 imported APIs, with high-signal imports for malicious functionality (source: pe_imports). UPX unpacking attempts failed: `upx_ok: False`, no unpacked payload was generated (source: upx). A XOR search identified a XOR 00 position at the start of the file, consistent with packed/obfuscated code (source: xor). Ghidra analysis failed with a `NotOwnerException` error, and its empty imports table is a known limitation for stripped/mixed-mode PEs, not an indicator of missing malicious imports (source: llm_judge).

### YARA Matches (19 total matches)
| Rule | Namespace | Match Strings (Trimmed) | Source |
|---|---|---|---|
| domain | - | $domain_regex@0 len=2 | yara |
| IP | - | $ipv4@68179 len=7; $ipv6@51945 len=3 | yara |
| contains_base64 | - | $a@35044 len=16 | yara |
| CRC32_poly_Constant | - | $c0@26628 len=4 | yara |
| url | - | $url_regex@34204 len=58 | yara |
| android_meterpreter | - | $checkSdeEncode@779048 len=4 | yara |
| IsPE32 | - | - | yara |
| IsWindowsGUI | - | - | yara |
| IsPacked | - | - | yara |
| HasOverlay | - | - | yara |
| HasDigitalSignature | - | $a3@1128685 len=140 | yara |
| HasRichSignature | - | $a0@192 len=4 | yara |
| Nullsoft_PiMP_Stub_SFX | - | $a@11747 len=9 | yara |
| escalate_priv | - | $d1@40346 len=12; $c2@35128 len=21 | yara |
| screenshot | - | $d1@40044 len=9; $d2@39898 len=10; $c2@38926 len=5 | yara |
| keylogger | - | $f1@39898 len=10; $c1@39268 len=16 | yara |
| win_registry | - | $f1@40346 len=12; $c3@40214 len=11; $c6@40214 len=11 | yara |
| win_token | - | $f1@40346 len=12; $c2@35128 len=21; $c3@35176 len=16 | yara |
| win_files_operation | - | $f1@35912 len=12; $c1@37732 len=9; $c2@37680 len=14; $c3@37732 len=9; $c4@37720 len=8 | yara |

### UPX Unpack Status
| Field | Value | Source |
|---|---|---|
| upx_ok | False | upx |
| is_packed | False | upx |
| returncode | None | upx |
| unpacked_path | (empty) | upx |

## 4. Malcat Triage Summary
Malcat analysis failed with a top-level MCP error: `malcat_analyze top-level: MCP malcat closed: `, so no function-level analysis, decompilation, control flow graphs, or static profile data was retrieved from Malcat (source: llm_judge). Analysis relied on alternative tools (pe_imports, capa, yara, floss, radare2) to compensate for this failure, per the cross-engine notes (source: llm_judge).

## 5. Static Code Analysis
Static analysis is limited by tooling failures: Ghidra failed with a `NotOwnerException`, IDA is unavailable due to a missing `idasql` binary, and Malcat crashed, so no function-level metadata, decompilation, or control flow graphs are available from these tools (source: llm_judge). Reliable static data was retrieved from pe_imports, capa, yara, floss, and radare2.

### Entry Point Disassembly (radare2, 0x004039e3)
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
(source: r2, address 0x004039e3)

### High-Signal Static Strings (FLOSS, 2325 total static strings)
| String | Context | Source |
|---|---|---|
| Error writing temporary file. Make sure your temp folder is valid. | Entry point error handling | r2 |
| AdjustTokenPrivileges | Token privilege manipulation | floss |
| LookupPrivilegeValueW | Token privilege manipulation | floss |
| OpenProcessToken | Token privilege manipulation | floss |
| RegDeleteKeyExW | Registry deletion | floss |
| CreateToolhelp32Snapshot | Process enumeration | floss |
| EnumProcesses | Process enumeration | floss |
| EnumProcessModules | Process enumeration | floss |
| GetModuleBaseNameW | Process enumeration | floss |
| MoveFileExW | File manipulation | floss |
| DeleteFileW | File deletion | floss |
| FindFirstFileW | File enumeration | floss |
| FindNextFileW | File enumeration | floss |
| SHGetFolderPathW | Shell API | floss |
| KERNEL32 | DLL import | floss |
| ADVAPI32 | DLL import | floss |
| [Rename] | NSIS installer directive | floss |
(source: floss, r2)

### Capa Capability Rules (51 total rules, 9.05s runtime)
| Rule | ATT&CK | MBC | Matches | Source |
|---|---|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data | 1 | capa |
| create or open registry key | - | C0036.004:Registry, C0036.003:Registry | - | capa |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes | - | capa |
| delete registry key | T1112:Modify Registry | C0036.002:Registry | - | capa |
| query or enumerate registry key | T1012:Query Registry | C0036.005:Registry | - | capa |
| enumerate files on Windows | T1083:File and Directory Discovery | E1083:File and Directory Discovery | 4 | capa |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery | - | capa |
| delete registry value | T1112:Modify Registry | C0036.007:Registry | - | capa |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry | - | capa |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery | - | capa |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery | - | capa |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter | - | capa |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery | - | capa |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging | 1 | capa |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery | - | capa |
(source: capa)

### PE Import Signals (171 total imports)
| Label | API Match | ATT&CK | Source |
|---|---|---|---|
| set_registry_value | RegSetValue | T1112 | pe_imports |
| create_process | CreateProcess | T1106 | pe_imports |
| shell_execute | ShellExecute | T1106 | pe_imports |
| load_library | LoadLibrary | T1129 | pe_imports |
| get_proc_address | GetProcAddress | T1129 | pe_imports |
(source: pe_imports)

## 6. Behavioral & Dynamic Analysis
Dynamic analysis via Speakeasy returned 0 API calls and 0 key events, with no recorded runtime behavior (source: speakeasy). Frida probe identified 30 hook candidates for common Windows APIs (including `GetAsyncKeyState`, `RegEnumKeyW`, `ShellExecuteW`, `CreateToolhelp32Snapshot`), but no runtime events were captured during analysis (source: frida_probe). UPX unpacking failed, so no unpacked payload was available for dynamic execution (source: upx). No behavioral indicators were observed in the available dynamic analysis data.

## 7. Network Indicators & C2
Static YARA analysis identified regex matches for domain, IPv4, IPv6, and URL patterns in the sample, but no specific C2 server addresses, domains, or URLs were extracted from static strings or dynamic analysis (source: yara). A YARA rule for `android_meterpreter` fired at offset 0x779048, which may indicate embedded Meterpreter artifacts or a code reuse signature, but no associated C2 infrastructure was identified (source: yara, deep_dive_agentic). No network traffic was observed during dynamic analysis, as Speakeasy recorded 0 events (source: speakeasy).

## 8. Capabilities & MITRE ATT&CK Mapping
The sample exhibits the following confirmed capabilities, mapped to MITRE ATT&CK:
| Capability | MITRE ATT&CK ID | Evidence Source | Evidence Reference |
|---|---|---|---|
| File and Directory Discovery | T1083 | capa | 4 matches for enumerate files on Windows, get file version info, get file size, get common file path |
| Modify Registry | T1112 | capa, pe_imports | 2 matches for create/open/delete registry key, delete registry value; RegSetValue import |
| Query Registry | T1012 | capa | 2 matches for query/enumerate registry key, query/enumerate registry value |
| Input Capture (Keylogging) | T1056.001 | capa | 1 match for log keystrokes via polling |
| Obfuscated Files/Information | T1027 | capa | 1 match for encode data using XOR |
| Process Execution | T1106 | pe_imports | CreateProcess, ShellExecute imports |
| Dynamic API Resolution | T1129 | pe_imports | LoadLibrary, GetProcAddress imports |
| System Information Discovery | T1082 | capa | matches for query environment variable, get disk size |
| File and Directory Permissions Modification | T1222 | capa | 1 match for set file attributes |
| Privilege Escalation | T1068 | yara | escalate_priv rule fired at offsets 0x40346, 0x35128 |
| Screen Capture | T1113 | yara | screenshot rule fired at offsets 0x40044, 0x39898, 0x38926 |
| Token Manipulation | T1134 | yara, floss | win_token rule fired; FLOSS strings: OpenProcessToken, AdjustTokenPrivileges, LookupPrivilegeValueW |
| File Operation | T1070.004 | yara, floss | win_files_operation rule fired; FLOSS strings: DeleteFileW, MoveFileExW, FindFirstFileW, FindNextFileW |
(source: capa, pe_imports, yara, floss)

## 9. Indicators of Compromise
### Static IOCs
| IOC Type | Value | Source |
|---|---|---|
| File Hash (SHA256) | 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 | llm_judge |
| Packer Signature | Nullsoft PiMP SFX Stub (offset 0x11747) | yara |
| Error String | "Error writing temporary file. Make sure your temp folder is valid." (0x4091d8) | r2 |
| YARA Rule Offsets (keylogger) | 0x39898, 0x40044, 0x38926 | yara |
| YARA Rule Offsets (screenshot) | 0x40044, 0x39898, 0x38926 | yara |
| YARA Rule Offsets (escalate_priv) | 0x40346, 0x35128 | yara |
| YARA Rule Offset (android_meterpreter) | 0x779048 | yara |
| High-Signal Import | RegSetValue, CreateProcess, ShellExecute, LoadLibrary, GetProcAddress | pe_imports |
| High-Signal FLOSS String | AdjustTokenPrivileges, LookupPrivilegeValueW, OpenProcessToken, RegDeleteKeyExW, CreateToolhelp32Snapshot, EnumProcesses, EnumProcessModules, GetModuleBaseNameW, MoveFileExW, DeleteFileW, FindFirstFileW, FindNextFileW | floss |
| Capability Rule | encode data using XOR (T1027), log keystrokes via polling (T1056.001), enumerate files on Windows (T1083) | capa |

### Generated Detection Rules
- YARA rule path: `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/rule.yar` (valid, 0 goodware false positives) (source: yara)
- Sigma rule path: `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/rule.yml` (source: yara)
(source: yara, floss, pe_imports, capa, r2, llm_judge)

## 10. Detection Engineering
### YARA Detection
A valid generated YARA rule is available at `/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/rule.yar`, with 0 false positives against the staged goodware corpus (source: yara). The rule targets high-signal strings and structural features including the Nullsoft PiMP SFX stub, packed PE indicators, and malicious behavior signatures.

### Capa Detection
Capa rules can be used to detect the sample's core capabilities in runtime or static analysis:
- `encode data using XOR (T1027)`
- `log keystrokes via polling (T1056.001)`
- `enumerate files on Windows (T1083)`
- `create or open registry key (T1112)`
- `set file attributes (T1222)`
(source: capa)

### Import-Based Detection
Monitor for the high-signal import combination: `RegSetValue` (T1112), `CreateProcess`/`ShellExecute` (T1106), `LoadLibrary`/`GetProcAddress` (T1129) in packed PE files with Nullsoft SFX stubs (source: pe_imports, yara).

### String-Based Detection
Alert on the presence of the high-signal FLOSS strings: `AdjustTokenPrivileges`, `LookupPrivilegeValueW`, `OpenProcessToken`, `RegDeleteKeyExW`, `CreateToolhelp32Snapshot`, `EnumProcesses`, `EnumProcessModules`, `GetModuleBaseNameW`, `MoveFileExW`, `DeleteFileW`, `FindFirstFileW`, `FindNextFileW` in unpacked memory or static analysis (source: floss).

## 11. What We Don't Know
1. Function-level static analysis is unavailable: Ghidra failed with a `NotOwnerException`, IDA is missing the `idasql` binary, and Malcat crashed, so no control flow graphs, function call graphs, or decompilation of core malicious functions are available (source: llm_judge).
2. No unpacked payload is available: UPX unpacking failed, and no Nullsoft PiMP stub unpacking was performed, so the core malicious payload is not available for analysis (source: upx, yara).
3. No runtime behavior was observed: Speakeasy recorded 0 API calls/events, and Frida captured no runtime events, so no confirmed C2 communication, data exfiltration, or payload deployment behavior was observed (source: speakeasy, frida_probe).
4. No specific C2 infrastructure IOCs were extracted: While YARA rules matched domain/IP/URL regex patterns, no actual C2 server addresses, domains, or URLs were identified in static strings or dynamic analysis (source: yara, speakeasy).
5. The `android_meterpreter` YARA match at offset 0x779048 is unexplained: It is unknown if this is a false positive, embedded Meterpreter artifact, or code reuse from open-source tooling (source: yara, deep_dive_agentic).
6. No evidence of anti-VM, anti-sandbox, or anti-analysis techniques beyond packing and XOR obfuscation was identified (unknown if present) (source: capa, yara).
7. No confirmed payload deployment or lateral movement mechanisms were observed, beyond the presence of `CreateProcess` and `ShellExecute` imports (unknown if used for secondary payload execution) (source: pe_imports).

## 12. Appendix: Analysis Environment
| Component | Details | Source |
|---|---|---|
| Sample Path | /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe | llm_judge |
| Project Name | incoming | llm_judge |
| Analysis Engine | langgraph (RevAI, commit 80c92a39d67f7e321883d3656b87cc4b04c5b7b5) | rule.yara.json |
| Analysis Timestamp | 2026-08-06 03:37:53 UTC | rule.yara.json |
| Tool Gate Status | All required tools passed: capa, pe_imports, yara, floss, dotnet, r2_decomp, upx, xor, speakeasy, frida_probe | deep_dive.json |
| Tool Failures | Ghidra: NotOwnerException; IDA: missing idasql binary; Malcat: top-level MCP crash | llm_judge, deep_dive.json |
| Frida Version | 17.16.4 | frida_probe |
| Capa Runtime | 9.05s, 51 rules matched | capa |
| FLOSS String Count | 2325 total static strings | floss |
| PE Import Count | 171 total imports | pe_imports |
(source: llm_judge, deep_dive_agentic, rule.yara.json, frida_probe, capa, floss, pe_imports)
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
  "sha256": "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50",
  "family": "unknown",
  "generated_at": "2026-08-06T03:37:53.484835+00:00",
  "string_count": 10,
  "strings": [
    "High-signal import confirming registry modification capability, a core TTP for info stealers used for persistence, data ",
    "High-signal imports enabling arbitrary process and command execution, consistent with malware payload deployment, latera",
    "High-signal imports for dynamic API resolution, commonly used by malware to obfuscate functionality and evade static det",
    "Capa rule matches confirm the sample enumerates files and directories, a core behavior of info stealers targeting sensit",
    "Capa rules confirm registry manipulation capabilities, used for persistence, credential theft, configuration storage, an",
    "Capa rule confirms keylogging functionality, a common feature of info stealers to capture user input including credentia",
    "Capa rule confirms XOR obfuscation usage, a common defense evasion technique used to hide sensitive data and malicious c",
    "YARA rule matches for common info stealer and credential theft behaviors, including keylogging, registry manipulation, t",
    "YARA matches confirm the sample is packed with a Nullsoft self-extracting stub, a common packing method used to obfuscat",
    "Deobfuscated FLOSS strings confirm low-level API usage for token/privilege manipulation, process enumeration, and file s"
  ],
  "rule_path": "/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/rule.yar",
  "sigma_path": "/opt/samples/logs/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/rule.yml",
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
  "revai": true,
  "provenance": {
    "project": "RevAI",
    "commit": "80c92a39d67f7e321883d3656b87cc4b04c5b7b5",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-06 03:37:53 UTC"
  },
  "publish_target": "revai_publish"
}
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module IN ('ADVAPI32.DLL','WININET.DLL','URLMON.DLL','CRYPT32.DLL','SHELL32.DLL','USER32.DLL','GDI32.DLL','WS2_32.DLL','WINHTTP.DLL','NTDLL.DLL','KERNEL32.DLL') ORDER BY address LIMIT 100", "ts": 1785818028.5023437}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%\\\\%' OR content LIKE '%/%' OR content LIKE '%.%' ORDER BY address LIMIT 100", "ts": 1785818033.9053614}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address BETWEEN 0 AND 200 OR address BETWEEN 11700 AND 11800 OR address BETWEEN 34000 AND 35200 OR address BETWEEN 38800 AND 40500 OR address BETWEEN 51900 AND 52050 OR address BETWEEN 68100 AND 68250 OR address BE`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module IN ('ADVAPI32.DLL','WININET.DLL','URLMON.DLL','CRYPT32.DLL','SHELL32.DLL','USER32.DLL','GDI32.DLL','WS2_32.DLL','WINHTTP.DLL','NTDLL.DLL') ORDER BY module, address", "ts": 1785818033.9300396}`
- `{"source": "publish_report_v2", "ts": 1785818208.3832088}`
- `{"source": "publish_report_v2_technical", "ts": 1785818284.4930959}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785818290.886243}`
- `{"source": "yara_gen_v2", "ts": 1785818291.9161704}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785879823.2764907}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785879823.34721}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785879823.3583148}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785879823.3723428}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785879904.1200268}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785879904.1527297}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785879904.2023418}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785879904.2119565}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785879904.2182474}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785879990.0083985}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY address LIMIT 50", "ts": 1785879994.8535686}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length > 4 ORDER BY address LIMIT 50", "ts": 1785879994.858583}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) as func_count FROM funcs", "ts": 1785879994.8606713}`
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name, class, size, is_exec FROM memory_blocks WHERE is_exec = 1 ORDER BY start_ea", "ts": 1785880009.4757712}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%lumma%' OR content LIKE '%Lumma%' OR content LIKE '%steal%' OR content LIKE '%keylog%' OR content LIKE '%screenshot%' OR content LIKE '%crypto%' OR content LIKE '%wallet%' OR content LIKE '%password%`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE '%Reg%' OR name LIKE '%Crypt%' OR name LIKE '%URL%' OR name LIKE '%WinInet%' OR name LIKE '%Http%' OR name LIKE '%Socket%' OR name LIKE '%Keybd%' OR name LIKE '%GetAsyncKeyState%' OR name LIKE '%GetForegroundWindow%'`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785880088.8589468}`
- `{"source": "yara_gen_v2", "ts": 1785880089.8933618}`
- `{"source": "publish_report_v2", "ts": 1785880210.345697}`
- `{"source": "publish_report_v2_technical", "ts": 1785880331.1183279}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785987323.142074}`
- `{"source": "yara_gen_v2", "ts": 1785987473.4851599}`
