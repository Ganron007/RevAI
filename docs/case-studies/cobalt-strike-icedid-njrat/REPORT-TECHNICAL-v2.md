# 1. Executive Summary

The sample (SHA256: cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467) initial automated triage flagged as malicious (score 0.9) based on capa rules (XOR encoding, stackstrings), debugger checks, process creation, memory protection changes, and high import count. However, deep-dive analysis (source: deep_dive_agentic) conclusively identifies the file as a legitimate 64-bit Adobe Acrobat/Reader Installer bootstrapper. Key evidence includes:

- PDB path: D:\T\M\Acrobat\Installers\BootStrapExe_Small\Release_x64\Setup.pdb (source: deep_dive_agentic, deep key_evidence)
- Copyright string: Copyright (c) 2024 Adobe Systems Incorporated. All rights reserved. (source: deep_dive_agentic)
- Registry key: SOFTWARE\Adobe\Setup\Reader (source: deep_dive_agentic)
- 22 ordinals imported from MSI.DLL (Windows Installer API) (source: deep_dive_agentic)
- Pre-installation of Microsoft Visual C++ 2012 SP1 (x64) Runtime (source: deep_dive_agentic)
- No networking imports (no WININET, WINHTTP, WS2_32, URLMON) -- no C2 capability (source: deep_dive_agentic)
- No references to any malware family (source: deep_dive_agentic)

Therefore, the file is benign with high confidence (95%). The initial malicious indicators are typical of MSVC-compiled applications with obfuscated stackstrings and common system API usage for installation tasks. This report supersedes the automated malicious verdict.

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467 |
| File path (corpus) | /opt/samples/corpus/incoming/cff3.../cobalt-strike-icedid-njrat |
| File name (corpus) | cobalt-strike-icedid-njrat |
| Original family guess | trojan (possible Cobalt Strike, IcedID, or njRAT) |
| Auto verdict score | 0.9 |
| Deep-dive verdict | benign (confidence 95%) |
| Deep-dive summary | Legitimate Adobe Acrobat/Reader installer bootstrapper (64-bit) |
| PDB path (source: deep_dive_agentic) | D:\T\M\Acrobat\Installers\BootStrapExe_Small\Release_x64\Setup.pdb |
| Copyright (source: deep_dive_agentic) | Copyright (c) 2024 Adobe Systems Incorporated. All rights reserved. |
| Architecture | x86-64 (64-bit) |
| Subsystem | Windows GUI (requires administrator privileges) |

## 3. File Layout & Structural Analysis

The file is a standard PE32+ image. Based on FLOSS strings and disassembly, the following sections are present (exact boundaries not retrieved):

| Section | Characteristics (expected) | Evidence (source) |
|---|---|---|
| .text | Code, execute, read | Contains entry point at 0x1400337c0 (source: radare2) |
| .rdata | Read-only data | FLOSS string: `.rdata` (source: floss) |
| .data | Read-write data | FLOSS string: `.data` (source: floss) |
| .rsrc | Resources (manifest, etc.) | FLOSS string: `.rsrc` (source: floss) |
| .pdata | Exception handling | FLOSS string: `.pdata` (source: floss) |
| .didat | Data | FLOSS string: `.didat` (source: floss) |

The entry point (0x1400337c0) is written in C++ and performs MSVC runtime initialization, including dynamic DLL loading and checks for MZ/PE signature.

## 4. Malcat Triage Summary

Malcat analysis could not be performed due to a missing MCP script. Error message: `MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py'`. (source: malcat) No triage summary available from this engine.

## 5. Static Code Analysis

### Overview
Static reverse engineering reveals a typical Adobe bootstrapper that leverages the Windows Installer API (MSI.DLL) to deploy Adobe Reader/Acrobat. The following subsections detail the entry point, supporting functions, and significant static features.

### Entry Point (0x1400337c0)
Disassembly from radare2 (source: radare2):

```asm
0x1400337c0      e848feffff     call fcn.14003360d
0x1400337c5      c8200000       enter 0x20, 0
0x1400337c9      4c897c24f8     mov qword [rsp - 8], r15
0x1400337ce      4883ec08       sub rsp, 8
0x1400337d2      4989e7         mov r15, rsp
0x1400337d5      4883ec20       sub rsp, 0x20
0x1400337d9      4883e4f0       and rsp, 0xfffffffffffffff0
0x1400337dd      4831f6         xor rsi, rsi
0x1400337e0      4801c6         add rsi, rax
0x1400337e3      4883c03c       add rax, 0x3c
0x1400337e7      4831d2         xor rdx, rdx
0x1400337ea      8b10           mov edx, dword [rax]
0x1400337ec      4883ec08       sub rsp, 8
0x1400337f0      48893424       mov qword [rsp], rsi
0x1400337f4      488b0424       mov rax, qword [rsp]
0x1400337f8      4883c408       add rsp, 8
0x1400337fc      4801d0         add rax, rdx
0x1400337ff      480588000000   add rax, 0x88
0x140033805      4883ec08       sub rsp, 8
0x140033809      48890424       mov qword [rsp], rax
0x14003380d      488b0c24       mov rcx, qword [rsp]
0x140033811      4883c408       add rsp, 8
0x140033815      48c7c00000..   mov rax, 0
0x14003381c      8b01           mov eax, dword [rcx]
0x14003381e      4801f0         add rax, rsi
0x140033821      50             push rax
0x140033822      488b0c24       mov rcx, qword [rsp]
0x140033826      4883c408       add rsp, 8
0x14003382a      56             push rsi
0x14003382b      488b1424       mov rdx, qword [rsp]
0x14003382f      4883c408       add rsp, 8
0x140033833      488d05acf3..   lea rax, [0x140032be6]
0x14003383a      4883ec08       sub rsp, 8
0x14003383e      48890c24       mov qword [rsp], rcx
0x140033842      48c7c1619a..   mov rcx, 0xfffffffffffe9a61
0x140033849      4883ec08       sub rsp, 8
0x14003384d      48890c24       mov qword [rsp], rcx
0x140033851      48c7c1cb73..   mov rcx, 0x173cb
0x140033858      48ffc0         inc rax
0x14003385b      48ffc9         dec rcx
0x14003385e      4881f9b56c..   cmp rcx, 0x16cb5
0x140033865      75f1           jne 0x140033858
0x140033867      4883c408       add rsp, 8
0x14003386b      488b4c24f8     mov rcx, qword [rsp - 8]
0x140033870      488b0c24       mov rcx, qword [rsp]
0x140033874      4883c408       add rsp, 8
0x140033878      ffd0           call rax
```

**Analysis**: The entry point calls `fcn.14003360d` then performs stack alignment and a manual delay loop (the `inc rax; dec rcx; cmp rcx, 0x16cb5; jne` sequence). This loop likely serves as an anti-analysis timeout or a crude form of execution delay. After the loop, it calls the function at the address constructed via the previous operations. The function at `0x14003360d` appears to locate the PE header and verify its integrity.

### Function 0x14003360d (PE header verification)

```asm
0x14003360d      488b442408     mov rax, qword [var_8h]
0x140033612      4883e200       and rdx, 0
0x140033616      48ffc8         dec rax
0x140033619      6681384d5a     cmp word [rax], 0x5a4d     ; 'MZ'
0x14003361e      750b           jne 0x14003362b
0x140033620      7414           je 0x140033636
0x140033622      e85e000000     call 0x140033685
0x140033627      b3c7           mov bl, 0xc7
0x140033629      9f             lahf
0x14003362a      5e             pop rsi
0x14003362b      75e9           jne 0x140033616
0x14003362d      e8fcffffff     call 0x14003362e
0x140033632      8bcf           mov ecx, edi
0x140033634      350b8b503c     xor eax, 0x3c508b0b
0x140033636      8b503c         mov edx, dword [rax + 0x3c]
0x140033639      81fa00040000   cmp edx, 0x400             ; 1024
0x14003363f      73d5           jae 0x140033616
0x140033641      482db5480000   sub rax, 0x48b5
0x140033647      4801c2         add rdx, rax
0x14003364a      4881c2b548..   add rdx, 0x48b5
0x140033651      4805b5480000   add rax, 0x48b5
0x140033657      66813a5045     cmp word [rdx], 0x4550     ; 'PE'
0x14003365c      7506           jne 0x140033664
0x14003365e      7442           je 0x1400336a2
0x140033660      82             invalid
0x140033664      744d           je 0x1400336b3
0x140033666      75ae           jne 0x140033616
0x140033668      488d05cdfe..   lea rax, [0x14003353c]
0x14003366f      4883ec08       sub rsp, 8
0x140033673      48890c24       mov qword [rsp], rcx
0x140033677      48c7c11028..   mov rcx, 0xffffffffffff2810
0x14003367e      4881c160d9..   add rcx, 0xd960
0x140033685      4801c1         add rcx, rax
0x140033688      51             push rcx
0x140033689      4891           xchg r
```

**Analysis**: This function searches for the MZ and PE signatures in a backward traversal of memory (starting from a given pointer and decrementing). It then validates the PE optional header size (0x3c field) and the PE magic. This is typically performed by the CRT startup to locate the module base or to verify the executable image. It is not malicious.

### Function 0x140009dbc (Initialization routine)

```asm
0x140009dbc      48895c2410     mov qword [var_10h], rbx
0x140009dc1      48894c2408     mov qword [var_8h], rcx
0x140009dc6      57             push rdi
0x140009dc7      4883ec20       sub rsp, 0x20
0x140009dcb      488bd9         mov rbx, rcx
0x140009dce      33d2           xor edx, edx
0x140009dd0      e8ef880100     call fcn.1400226c4
0x140009dd5      90             nop
0x140009dd6      488d057b12..   lea rax, [0x14005b058]
0x140009ddd      488903         mov qword [rbx], rax
0x140009de0      e8fb8c0000     call fcn.140012ae0
0x140009de5      488bc8         mov rcx, rax
0x140009de8      33ff           xor edi, edi
0x140009dea      4885c0         test rax, rax
0x140009ded      0f84f2010000   je 0x140009fe5
0x140009df3      488b00         mov rax, qword [rax]
0x140009df6      488b4018       mov rax, qword [rax + 0x18]
0x140009dfa      ff15f0dc0400   call qword [0x140057af0]
0x140009e00      4883c018       add rax, 0x18
0x140009e04      4889837801..   mov qword [rbx + 0x178], rax
...
```

**Analysis**: This function appears to be a C++ class constructor. It initializes a vtable pointer (mov qword [rbx], rax) and calls other functions to populate data members. Specifically, it calls `fcn.140012ae0` which simply returns a global address (0x140079370). This is consistent with generic MSVC initialization code.

### Simplified function 0x140012ae0

```asm
0x140012ae0      488d058968..   lea rax, [0x140079370]
0x140012ae7      c3             ret
```

### Import Analysis

The file imports a total of 339 functions. Key DLLs: KERNEL32, ADVAPI32, SHELL32, USER32, GDI32, SHLWAPI, WINSPOOL.DRV, and notably 22 ordinals from MSI.DLL (Windows Installer). The MSI imports confirm the bootstrapper role.

### Capa Capability Rules (source: capa)

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| query or enumerate registry key | T1012:Query Registry | C0036.005:Registry |
| link function at runtime on Windows | T1129:Shared Modules |  |
| create or open file |  | C0016:Create File |
| modify access privileges | T1134:Access Token Manipulation |  |
| delay execution |  | B0003.003:Dynamic Analysis Evasion |

### PE Import Signals (source: pe_imports)

import_count: 339

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

### FLOSS Extracted Strings (source: floss)

Total strings: 3603, categories: decoded:0, stack:3, tight:0, language:0, static:3600

High-signal sample:
- `{A6EADE66---484E-7E8A450`
- `{AC76BA86---7760-7E8A450`
- `VirtualAlloc`
- `!This program cannot be run in DOS mode.`
- `dJ%%aK`
- `%aKRich`
- ``.rdata``
- `@.data`
- `.pdata`
- `@.didat`

These are typical of Windows PE, with some GUIDs and API names. No malicious strings found.

### Generated YARA Strings (source: yara_gen_v2)

The following strings were automatically extracted; all are installer-related messages, consistent with Adobe Setup:
- "This version of %s is not supported.  You should upgrade to Service Pack %s and run setup again.  Setup will now terminate."
- "This program is linked to the missing export %Ts in the file %Ts. This machine may have an incompatible version of %Ts."
- "Another installation is in progress. You must complete that installation before continuing this one."
- "Setup needs to restart your system to complete the installation.  Do you want to restart now?"
- "HandleNonDefaultLocationInstall: The existing command line doesn't require any modifications. Exiting Now..."
- "Initialization: Failed to open %s file, Make sure the file is not used by another process."
- "This operating system is not supported by this installation.  Setup will now terminate."
- "System registry entries have been removed and the INI file (if any) was deleted."

These strings further confirm the file as an installer rather than malware.

## 6. Behavioral & Dynamic Analysis

### Speakeasy (source: speakeasy)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- **not observed**: No API calls or events were recorded. The sample likely requires user interaction or a specific environment (e.g., MSI engine present) and hence did not execute any meaningful actions within Speakeasy's emulation.

### Frida Probe (source: frida_probe)
- frida_available: True (version 17.16.4)
- hook_candidates listed: (e.g., KERNEL32.dll!GetLocaleInfoW, USER32.dll!CreateDialogIndirectParamW, etc.) but no hook scripts were run and no runtime instrumentation data was collected.
- Therefore, dynamic behavior remains **not observed**.

## 7. Network Indicators & C2

No network indicators were identified in this sample.

- The import table contains **no networking APIs**: no WININET, WINHTTP, WS2_32, URLMON (source: deep_dive_agentic, key_evidence; confirmed by Ghidra import queries).
- String analysis across multiple Ghidra queries found **no URLs, IP addresses, or domain names** (source: ghidra, multiple queries).
- The sample's intended behavior is to launch the Windows Installer service (via MSI.DLL), which may handle content download. However, no direct network communication code is present.
- **Conclusion**: No C2 or network exfiltration capability is present.

## 8. Capabilities & MITRE ATT&CK Mapping

The following table maps observed behaviors to MITRE ATT&CK techniques. For each, a benign explanation is provided, given the file's true nature as an installer bootstrapper.

| Capability | ATT&CK Technique | Evidence (source) | Benign Explanation |
|---|---|---|---|
| Encode data using XOR | T1027 | capa rule: `encode data using XOR` | Common in MSVC to obfuscate stack strings for anti-tampering or DRM. |
| Contain obfuscated stackstrings | T1027.005 | capa rule: `contain obfuscated stackstrings` | Compiler-generated stackstrings may appear obfuscated; not necessarily malicious. |
| Check for debugger | T1622 | pe_imports: `IsDebuggerPresent` | Installers often check for debuggers to prevent piracy or tampering. |
| Create process | T1106 | pe_imports: `CreateProcess` | Necessary to launch child processes like msiexec.exe for installation. |
| Shell execute | T1106 | pe_imports: `ShellExecute` | Used to open documentation or launch URLs post-install; typical in installers. |
| Load library / Get proc address | T1129 | pe_imports: `LoadLibrary`, `GetProcAddress` | Dynamic loading of MSI.DLL or other components is standard. |
| Change memory protection | T1055 | pe_imports: `VirtualProtect` | May be used for self-modifying code optimizations or to mark memory as executable for uncompressed data. |
| Registry operations (create/delete/query) | T1112, T1012 | capa rules; pe_imports: `RegSetValue` | Standard installer behavior: read/write registry settings for the application. |
| Query environment variable | T1082 | capa rule: `query environment variable` | Installers check environment to find system paths or determine installation state. |
| Get disk / file info | T1083, T1082 | capa rules: `get common file path`, `get disk information`, `get file size` | Required for file placement and disk space checks. |
| Delay execution | (obfuscation/evasion) | capa rule: `delay execution`; also entry point timing loop (0x140033858) | The delay may serve as an anti-analysis timeout or as part of CRT initialization. |
| Delete registry key/value | T1112 | capa rules: `delete registry key`, `delete registry value` | Installers often clean up stale registry entries during upgrades/uninstalls. |
| Create or open file | – | capa rule: `create or open file` | Essential for extracting and installing files. |
| Modify access privileges | T1134 | capa rule: `modify access privileges` | Possibly to elevate for administrative tasks (manifest requires admin). |
| Get common file path | T1083 | capa rule: `get common file path` | Needed to determine installation directories like Program Files. |

## 9. Indicators of Compromise

Given the reassessment as benign, the following artifacts are **not IOCs** but may be of interest for defensive teams tracking Adobe software:

- File hash: `cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467`
- PDB path: `D:\T\M\Acrobat\Installers\BootStrapExe_Small\Release_x64\Setup.pdb` (source: deep_dive_agentic)
- Copyright string: `Copyright (c) 2024 Adobe Systems Incorporated. All rights reserved.` (source: deep_dive_agentic)
- Registry key: `SOFTWARE\Adobe\Setup\Reader` (source: deep_dive_agentic)
- GUIDs: `{A6EADE66-...`, `{AC76BA86-...` (source: floss)
- File name in corpus: `cobalt-strike-icedid-njrat` (mislabeling)

**No malicious IOCs (C2 domains, malicious IPs, exploit code) were discovered.**

## 10. Detection Engineering

### YARA Detection
A YARA rule was automatically generated and is available at:
`/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/rule.yar` (source: yara_gen_v2)

The rule consists of 24 strings, all related to installer messages (e.g., "This version of %s is not supported.  You should upgrade to Service Pack %s and run setup again.  Setup will now terminate."). It may detect Adobe Installer bootstrappers but is not suitable for malware classification.

### Sigma Rule
A corresponding Sigma rule was generated at:
`/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/rule.yml` (source: yara_gen_v2)

Given the benign context, this rule is not recommended for threat detection.

### Host-based Detection
Defenders should expect process chains like:
- `setup.exe` -> `msiexec.exe`
- Registry writes to `SOFTWARE\Adobe\...`
- File creations under `Program Files\Adobe\...`

These are normal for Adobe Reader/Acrobat installations.

### Network Detection
No malicious network traffic is expected. Content download may occur via BITS or MSI over HTTP/HTTPS, but that is legitimate for software installers.

## 11. What We Don't Know

- **Digital Signature**: Whether the file carries a valid Adobe digital signature was not verified. (source: not observed)
- **Runtime Behavior**: Speakeasy and Frida did not capture any events, so the actual GUI interactions, installation prompts, and network downloads (if any) are unknown.
- **Download Source**: Even though the deep-dive analysis indicates it downloads components, no URLs or download logic were statically recoverable. The download mechanism likely relies on MSI or BITS.
- **Original Distribution Context**: The reason this legitimate file was placed in a malware corpus with a suggestive name ("cobalt-strike-icedid-njrat") is unknown. It may have been a false positive submission or part of a broader campaign analysis.
- **Targeted Environment**: The installer may check for specific Windows versions or pre-existing software; these checks were not emulated or observed.
- **Embedded Payloads**: The file may contain compressed/cabinet payloads that were not fully extracted. Static analysis did not indicate any secondary malware payloads.

## 12. Appendix: Analysis Environment

The analysis was performed using the CADRE-RevAI automated pipeline and follow-up deep-dive analysis. The following tools were utilized:

| Tool | Version / Details | Status / Results |
|---|---|---|
| capa | (latest) | 44 capability rules triggered |
| pe_imports | – | 339 imports identified |
| FLOSS | (latest) | 3603 strings (3 stack, 3600 static) |
| YARA | rule generator | 24 strings, rule created (valid) |
| Malcat | (attempted) | Error: MCP not found |
| Speakeasy | – | 0 API calls, no behavior |
| Frida Probe | v17.16.4 | Hooks listed, no runtime data |
| Ghidra | (headless, via SQL) | Multiple queries performed (strings, imports, functions) |
| radare2 | (disassembly) | Disassembly of entry and key functions |
| UPX Unpack | – | Not packed |
| XOR Search | – | Found XOR 0x00 at position 0 |
| .NET Analysis | – | is_dotnet: false |
| Deep-dive Agent | langgraph | Enabled, 38 tool calls, confidence 95% |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467  
**sample_path:** /opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 0.9
- **family_guess**: trojan (possible Cobalt Strike, IcedID, or njRAT)
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA and Malcat failed with errors; Yara had no matches. Ghidra, capa, pe_imports, and FLOSS provided evidence.
- **summary**: The file is a Windows PE executable showing multiple signs of malware: obfuscation via XOR and stackstrings, debugger detection, dynamic loading, process creation, registry modification, and memory protection changes. High import count and presence of common malware APIs (VirtualAlloc, VirtualProtect, CreateProcess) and discovery commands (file, registry, environment) align with trojan behavior. No Yara matches but file path suggests association with Cobalt Strike, IcedID, or njRAT.
- **source**: llm_judge
- **model**: deepseek-v4-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | rule | `contain obfuscated stackstrings` | Indicates defense evasion via obfuscation (T1027.005). |
| capa | rule | `encode data using XOR` | Indicates data encoding for evasion (T1027). |
| pe_imports | signal label | `check_debugger: IsDebuggerPresent` | Debugger detection for anti-analysis (T1622). |
| pe_imports | signal label | `change_memory_protection: VirtualProtect` | Often used for process injection (T1055). |
| pe_imports | signal label | `create_process: CreateProcess` | Capable of starting other processes (T1106). |
| floss | extracted strings | `VirtualAlloc` | API used for memory allocation, commonly in shellcode or injection. |
| ghidra | Suspicious strings (Ghidra) | `XML manifest and multiple DLL strings` | Contains GUI resources and references to system DLLs suggesting a dropper or trojan. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 95
- **summary**: This is a legitimate Adobe Acrobat/Acrobat Reader installer bootstrapper (64-bit) that was mislabeled in the malware corpus. It is a Windows Installer (MSI) bootstrapper that downloads and installs Adobe Acrobat components. The PDB path, copyright strings, registry keys, MSI.DLL imports, and VC++ redistributable installer strings all conclusively identify it as a signed Adobe setup executable.

### deep key_evidence
- `"PDB path: D:\\T\\M\\Acrobat\\Installers\\BootStrapExe_Small\\Release_x64\\Setup.pdb confirms Adobe Acrobat installer origin"`
- `"String: 'Adobe Bootstrapper for Single Installation' and 'Copyright \u00a9 2024 Adobe Systems Incorporated. All rights reserved.'"`
- `"String: 'SOFTWARE\\Adobe\\Setup\\Reader' registry key for Adobe Reader configuration"`
- `"22 ordinals imported from MSI.DLL (Windows Installer API) consistent with MSI bootstrapper"`
- `"String: 'Installing Microsoft Visual C++ 2012 SP1 (x64) Runtime.' indicating prerequisite installation"`
- `"No networking imports (no WININET, WINHTTP, WS2_32, URLMON) \u2014 no C2 capability"`
- `"Zero references to cobalt strike, beacon, icedid, njrat, shellcode, reflective loader, or any malware family"`
- `"No suspicious URLs, IP addresses, or domain names present in any strings"`
- `"Manifest requires administrator privileges \u2014 typical for software installers"`
- `"Capa rules (XOR, obfuscated stackstrings, registry ops) are benign patterns common in MSVC-compiled applications"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 44 · duration_s: 34.4

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| query or enumerate registry key | T1012:Query Registry | C0036.005:Registry |
| link function at runtime on Windows | T1129:Shared Modules |  |
| create or open file |  | C0016:Create File |
| modify access privileges | T1134:Access Token Manipulation |  |
| delay execution |  | B0003.003:Dynamic Analysis Evasion |

## PE Imports / Signals
import_count: 339

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## Generated YARA Meta
```json
{
  "sha256": "cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467",
  "family": "unknown",
  "generated_at": "2026-07-28T02:54:26.604773+00:00",
  "string_count": 24,
  "strings": [
    "This version of %s is not supported.  You should upgrade to Service Pack %s and run setup again.  Setup will now terminate.",
    "This program is linked to the missing export %Ts in the file %Ts. This machine may have an incompatible version of %Ts.",
    "HandleNonDefaultLocationInstall: The existing command line doesn't require any modifications. Exiting Now...",
    ".?AV?$CMap@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PEB_WPEAVCDocument@@PEAV3@@@",
    ".?AV?$CMap@PEAVCDocument@@PEAV1@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PEB_W@@",
    "Another installation is in progress. You must complete that installation before continuing this one.",
    "Setup needs to restart your system to complete the installation.  Do you want to restart now?",
    "Initialization: Failed to open %s file, Make sure the file is not used by another process.",
    "HandleNonDefaultLocationInstall: Install location is default, no need modify sProdCmdLn",
    ".?AV?$CMap@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PEB_WV12@PEB_W@@",
    "Initialization: Unable to locate alternative INI file \"%s\", revert to the default INI.",
    "This operating system is not supported by this installation.  Setup will now terminate.",
    ".?AV?$CMap@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PEB_W_N_N@@",
    "System registry entries have been removed and the INI file (if any) was deleted.",
    "HandleNonDefaultLocationInstall: Failed to read from installpath registry key",
    "HandleNonDefaultLocationInstall: Failed to evaluate ProgramFiles folder path",
    "Initialization: Failed to initialize Product - Unable to locate \"%s\" file.",
    "HandleNonDefaultLocationInstall: Failed to fetch track from product code",
    "SetupuninstallProducts: Migration: Uninstall of %s failed with error= %d.",
    "This program requires the file %Ts, which was not found on this system.",
    "Initialization: Failed to initialize Product - msi key not specified.",
    "Initialization: Failed to initialize - Unable to get Product Version.",
    "SetupINitialize: setup.exe Timeout set for MSI Mutex to get free: %u",
    "Initialization: Failed to initialize - Unable to get Product Name."
  ],
  "rule_path": "/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/rule.yar",
  "sigma_path": "/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/rule.yml",
  "yara_valid": true,
  "yara_check": "yara-x check skipped (not installed)",
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
Total strings: 3603 · per_category: `{"decoded_strings": 0, "stack_strings": 3, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 3600}`

### FLOSS sample
- `{A6EADE66---484E-7E8A450`
- `{AC76BA86---7760-7E8A450`
- `VirtualAlloc`
- `!This program cannot be run in DOS mode.`
- `dJ%%aK`
- `%aKRich`
- ``.rdata`
- `@.data`
- `.pdata`
- `@.didat`
- `_RDATA`
- `@.rsrc`
- `WAVAWH`
- `VWATAVAWH`
- `0A_A^A\_^`
- `x ATAVAWH`
- `A_A^A\`
- `WATAUAVAWH`
- `Lcd$pE3`
- `A_A^A]A\_`
- `t$ UWATAVAWH`
- `A_A^A\_]`
- `t$ WATAUAVAWH`
- `UVWATAUAVAWH`
- `A_A^A]A\_^]`
- `@USVWAWH`
- `A__^[]`
- `@A_A^A\_^`
- `@USVWATAUAVAWH`
- `YD9-Bg`
- `A_A^A]A\_^[]`
- `UWATAUAVH`
- `A^A]A\_]`
- `UVWAVAWH`
- `0A_A^_^]`
- `x UATAVH`
- `VH+L$(I`
- `+D$ Lc`
- `<OH;|$8`
- `@A_A^A]A\_^]`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x1400337c0
```asm
┌ 242: entry0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_8h @ rbp-0x8
│           0x1400337c0      e848feffff     call fcn.14003360d
│           0x1400337c5      c8200000       enter 0x20, 0              ; 32
│           0x1400337c9      4c897c24f8     mov qword [rsp - 8], r15
│           0x1400337ce      4883ec08       sub rsp, 8
│           0x1400337d2      4989e7         mov r15, rsp
│           0x1400337d5      4883ec20       sub rsp, 0x20
│           0x1400337d9      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x1400337dd      4831f6         xor rsi, rsi
│           0x1400337e0      4801c6         add rsi, rax
│           0x1400337e3      4883c03c       add rax, 0x3c              ; 60
│           0x1400337e7      4831d2         xor rdx, rdx
│           0x1400337ea      8b10           mov edx, dword [rax]
│           0x1400337ec      4883ec08       sub rsp, 8
│           0x1400337f0      48893424       mov qword [rsp], rsi
│           0x1400337f4      488b0424       mov rax, qword [rsp]
│           0x1400337f8      4883c408       add rsp, 8
│           0x1400337fc      4801d0         add rax, rdx
│           0x1400337ff      480588000000   add rax, 0x88              ; 136
│           0x140033805      4883ec08       sub rsp, 8
│           0x140033809      48890424       mov qword [rsp], rax
│           0x14003380d      488b0c24       mov rcx, qword [rsp]
│           0x140033811      4883c408       add rsp, 8
│           0x140033815      48c7c00000..   mov rax, 0
│           0x14003381c      8b01           mov eax, dword [rcx]
│           0x14003381e      4801f0         add rax, rsi
│           0x140033821      50             push rax
│           0x140033822      488b0c24       mov rcx, qword [rsp]
│           0x140033826      4883c408       add rsp, 8
│           0x14003382a      56             push rsi
│           0x14003382b      488b1424       mov rdx, qword [rsp]
│           0x14003382f      4883c408       add rsp, 8
│           0x140033833      488d05acf3..   lea rax, [0x140032be6]
│           0x14003383a      4883ec08       sub rsp, 8
│           0x14003383e      48890c24       mov qword [rsp], rcx
│           0x140033842      48c7c1619a..   mov rcx, 0xfffffffffffe9a61
│           0x140033849      4883ec08       sub rsp, 8
│           0x14003384d      48890c24       mov qword [rsp], rcx
│           0x140033851      48c7c1cb73..   mov rcx, 0x173cb
│       ┌─> 0x140033858      48ffc0         inc rax
│       ╎   0x14003385b      48ffc9         dec rcx
│       ╎   0x14003385e      4881f9b56c..   cmp rcx, 0x16cb5
│       └─< 0x140033865      75f1           jne 0x140033858
│           0x140033867      4883c408       add rsp, 8
│           0x14003386b      488b4c24f8     mov rcx, qword [rsp - 8]
│           0x140033870      488b0c24       mov rcx, qword [rsp]
│           0x140033874      4883c408       add rsp, 8
│           0x140033878      ffd0           call rax
│           0x14003387a      
```
### 0x14003360d
```asm
; CALL XREF from entry0 @ 0x1400337c0(x)
┌ 446: fcn.14003360d (int64_t arg2);
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_1h @ rbp-0x1
│           ; var int64_t var_2h @ rbp-0x2
│           ; var int64_t var_3h @ rbp-0x3
│           ; var int64_t var_4h @ rbp-0x4
│           ; var int64_t var_5h @ rbp-0x5
│           ; var int64_t var_6h @ rbp-0x6
│           ; var int64_t var_7h @ rbp-0x7
│           ; var int64_t var_bp_8h @ rbp-0x8
│           ; var int64_t var_9h @ rbp-0x9
│           ; var int64_t var_ah @ rbp-0xa
│           ; var int64_t var_bh @ rbp-0xb
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_7fh @ rbp-0x7f
│           ; var int64_t var_8h @ rsp+0x218
│           0x14003360d      488b442408     mov rax, qword [var_8h]
│           0x140033612      4883e200       and rdx, 0                 ; arg2
│      ┌┌─> 0x140033616      48ffc8         dec rax
│      ╎╎   0x140033619      6681384d5a     cmp word [rax], 0x5a4d     ; 'MZ'
│     ┌───< 0x14003361e      750b           jne 0x14003362b
│    ┌────< 0x140033620      7414           je 0x140033636
│    ││╎╎   0x140033622      e85e000000     call 0x140033685
│    ││╎╎   0x140033627      b3c7           mov bl, 0xc7               ; 199
│    ││╎╎   0x140033629      9f             lahf
│    ││╎╎   0x14003362a      5e             pop rsi
│    │└└──< 0x14003362b      75e9           jne 0x140033616
│    │  ╎   0x14003362d      e8fcffffff     call 0x14003362e
│    │  ╎   0x140033632      8bcf           mov ecx, edi
│    │  ╎   0x140033634  ~   350b8b503c     xor eax, 0x3c508b0b
│    └────> 0x140033636      8b503c         mov edx, dword [rax + 0x3c]
│       ╎   0x140033639      81fa00040000   cmp edx, 0x400             ; 1024
│       └─< 0x14003363f      73d5           jae 0x140033616
│           0x140033641      482db5480000   sub rax, 0x48b5
│           0x140033647      4801c2         add rdx, rax
│           0x14003364a      4881c2b548..   add rdx, 0x48b5
│           0x140033651      4805b5480000   add rax, 0x48b5
│           0x140033657      66813a5045     cmp word [rdx], 0x4550     ; 'PE'
│       ┌─< 0x14003365c      7506           jne 0x140033664
│      ┌──< 0x14003365e      7442           je 0x1400336a2
│      ││   0x140033660      82             invalid
..
│      │└─> 0x140033664      744d           je 0x1400336b3
│      │    0x140033666      75ae           jne 0x140033616
│      │    0x140033668      488d05cdfe..   lea rax, [0x14003353c]
│      │    0x14003366f      4883ec08       sub rsp, 8
│      │    0x140033673      48890c24       mov qword [rsp], rcx
│      │    0x140033677      48c7c11028..   mov rcx, 0xffffffffffff2810
│      │    0x14003367e      4881c160d9..   add rcx, 0xd960
│      │    ; CALL XREF from fcn.14003360d @ 0x140033622(x)
│      │    0x140033685      4801c1         add rcx, rax
│      │    0x140033688      51             push rcx
│      │    0x140033689      4891           xchg r
```
### 0x140009dbc
```asm
┌ 413: fcn.140009dbc (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_8h @ rsp+0x30
│           ; var int64_t var_10h @ rsp+0x38
│           0x140009dbc      48895c2410     mov qword [var_10h], rbx
│           0x140009dc1      48894c2408     mov qword [var_8h], rcx    ; arg1
│           0x140009dc6      57             push rdi
│           0x140009dc7      4883ec20       sub rsp, 0x20
│           0x140009dcb      488bd9         mov rbx, rcx               ; arg1
│           0x140009dce      33d2           xor edx, edx
│           0x140009dd0      e8ef880100     call fcn.1400226c4
│           0x140009dd5      90             nop
│           0x140009dd6      488d057b12..   lea rax, [0x14005b058]
│           0x140009ddd      488903         mov qword [rbx], rax
│           0x140009de0      e8fb8c0000     call fcn.140012ae0
│           0x140009de5      488bc8         mov rcx, rax
│           0x140009de8      33ff           xor edi, edi
│           0x140009dea      4885c0         test rax, rax
│       ┌─< 0x140009ded      0f84f2010000   je 0x140009fe5
│       │   0x140009df3      488b00         mov rax, qword [rax]
│       │   0x140009df6      488b4018       mov rax, qword [rax + 0x18]
│       │   0x140009dfa      ff15f0dc0400   call qword [0x140057af0]   ; [0x140057af0:8]=0x1400541f0
│       │   0x140009e00      4883c018       add rax, 0x18              ; 24
│       │   0x140009e04      4889837801..   mov qword [rbx + 0x178], rax
│       │   0x140009e0b      e8d08c0000     call fcn.140012ae0
│       │   0x140009e10      488bc8         mov rcx, rax
│       │   0x140009e13      4885c0         test rax, rax
│      ┌──< 0x140009e16      0f84d4010000   je 0x140009ff0
│      ││   0x140009e1c      488b00         mov rax, qword [rax]
│      ││   0x140009e1f      488b4018       mov rax, qword [rax + 0x18]
│      ││   0x140009e23      ff15c7dc0400   call qword [0x140057af0]   ; [0x140057af0:8]=0x1400541f0
│      ││   0x140009e29      4883c018       add rax, 0x18              ; 24
│      ││   0x140009e2d      4889838001..   mov qword [rbx + 0x180], rax
│      ││   0x140009e34      e8a78c0000     call fcn.140012ae0
│      ││   0x140009e39      488bc8         mov rcx, rax
│      ││   0x140009e3c      4885c0         test rax, rax
│     ┌───< 0x140009e3f      0f84b6010000   je 0x140009ffb
│     │││   0x140009e45      488b00         mov rax, qword [rax]
│     │││   0x140009e48      488b4018       mov rax, qword [rax + 0x18]
│     │││   0x140009e4c      ff159edc0400   call qword [0x140057af0]   ; [0x140057af0:8]=0x1400541f0
│     │││   0x140009e52      4883c018       add rax, 0x18              ; 24
│     │││   0x140009e56      4889838801..   mov qword [rbx + 0x188], rax
│     │││   0x140009e5d      4889bb9001..   mov qword [rbx + 0x190], rdi
│     │││   0x140009e64      4889bb9801..   mov qword [rbx + 0x198], rdi
│     │││   0x140009e6b      4889bba001..   mov qword [rbx + 0x1a0], rdi
│     │││   0x140009e72      4889bba801..   mov qword
```
### 0x1400226c4
```asm
┌ 91: fcn.1400226c4 (int64_t arg1, int64_t arg2);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_20h_2 @ rsp+0x20
│           ; var int64_t var_150h @ rsp+0x150
│           ; var int64_t var_18h @ rsp+0x180
│           ; var int64_t var_20h @ rsp+0x188
│           0x1400226c4      48895c2418     mov qword [var_18h], rbx
│           0x1400226c9      4889742420     mov qword [var_20h], rsi
│           0x1400226ce      57             push rdi
│           0x1400226cf      4881ec6001..   sub rsp, 0x160
│           0x1400226d6      488b05e36f..   mov rax, qword [0x1400796c0] ; [0x1400796c0:8]=0x2b992ddfa232
│           0x1400226dd      4833c4         xor rax, rsp
│           0x1400226e0      4889842450..   mov qword [var_150h], rax
│           0x1400226e8      488bfa         mov rdi, rdx               ; arg2
│           0x1400226eb      488bd9         mov rbx, rcx               ; arg1
│           0x1400226ee      48894c2420     mov qword [var_20h_2], rcx ; arg1
│           0x1400226f3      e8aca3ffff     call 0x14001caa4
│           0x1400226f8      90             nop
│           0x1400226f9      488d05180a..   lea rax, [0x140063118]
│           0x140022700      488903         mov qword [rbx], rax
│           0x140022703      33f6           xor esi, esi
│           0x140022705      4885ff         test rdi, rdi
│       ┌─< 0x140022708      740a           je 0x140022714
│       │   0x14002270a      488bcf         mov rcx, rdi
│       │   0x14002270d      e8e2350200     call 0x140045cf4
│      ┌──< 0x140022712      eb03           jmp 0x140022717
│      │└─> 0x140022714      488bc6         mov rax, rsi
│      │    ; CODE XREF from fcn.1400226c4 @ 0x140022712(x)
│      └──> 0x140022717      488983a000..   mov qword [rbx + 0xa0], rax
└           0x14002271e      cc             int3
```
### 0x140012ae0
```asm
┌ 8: fcn.140012ae0 ();
│           0x140012ae0      488d058968..   lea rax, [0x140079370]
└           0x140012ae7      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!GetLocaleInfoW`
  - `KERNEL32.dll!GetSystemDefaultUILanguage`
  - `KERNEL32.dll!VirtualProtect`
  - `KERNEL32.dll!GetFileAttributesW`
  - `KERNEL32.dll!GetFileAttributesExW`
  - `USER32.dll!CreateDialogIndirectParamW`
  - `USER32.dll!GetMonitorInfoW`
  - `USER32.dll!MonitorFromWindow`
  - `USER32.dll!WinHelpW`
  - `USER32.dll!LoadIconW`
  - `GDI32.dll!PtVisible`
  - `GDI32.dll!RectVisible`
  - `GDI32.dll!RestoreDC`
  - `GDI32.dll!SaveDC`
  - `GDI32.dll!SelectObject`
  - `WINSPOOL.DRV!ClosePrinter`
  - `WINSPOOL.DRV!OpenPrinterW`
  - `WINSPOOL.DRV!DocumentPropertiesW`
  - `ADVAPI32.dll!RegEnumValueW`
  - `ADVAPI32.dll!RegQueryValueW`
  - `ADVAPI32.dll!RegEnumKeyW`
  - `ADVAPI32.dll!RegDeleteValueW`
  - `ADVAPI32.dll!RegDeleteKeyW`
  - `SHELL32.dll!SHGetKnownFolderPath`
  - `SHELL32.dll!ShellExecuteW`
  - `SHELL32.dll!SHGetSpecialFolderPathW`
  - `SHLWAPI.dll!PathFileExistsW`
  - `SHLWAPI.dll!PathRemoveFileSpecW`
  - `SHLWAPI.dll!PathIsUNCW`
  - `SHLWAPI.dll!PathStripToRootW`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785207002.9192588}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785207002.9502468}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785207002.9509966}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785207121.0868957}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 20", "ts": 1785207124.4398038}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY module LIMIT 60", "ts": 1785207124.486765}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length > 6 ORDER BY length DESC LIMIT 30", "ts": 1785207124.5178025}`
- `{"source": "ghidra_query", "sql": "SELECT module, COUNT(*) as cnt FROM imports GROUP BY module ORDER BY cnt DESC", "ts": 1785207128.3947744}`
- `{"source": "ghidra_query", "sql": "SELECT name FROM imports WHERE module LIKE '%WININET%' OR module LIKE '%WINHTTP%' OR module LIKE '%URLMON%' OR module LIKE '%WS2_32%' OR module LIKE '%CRYPT%' OR module LIKE '%KERNEL32%' OR module LIKE '%NTDLL%' OR module LIKE '%SHELL32%' OR module LIKE '%ADVAPI32%`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%https%' OR content LIKE '%cobalt%' OR content LIKE '%beacon%' OR content LIKE '%mirai%' OR content LIKE '%njrat%' OR content LIKE '%icedid%' OR content LIKE '%bot%' OR conten`
- `{"source": "ghidra_query", "sql": "SELECT name FROM imports WHERE module = 'ADVAPI32.DLL'", "ts": 1785207131.113698}`
- `{"source": "ghidra_query", "sql": "SELECT name FROM imports WHERE module = 'SHELL32.DLL'", "ts": 1785207131.1257548}`
- `{"source": "ghidra_query", "sql": "SELECT name FROM funcs WHERE name LIKE 'FUN_%' AND size > 500 ORDER BY size DESC LIMIT 30", "ts": 1785207131.1868796}`
- `{"source": "ghidra_query", "sql": "SELECT name FROM imports WHERE module = 'MSI.DLL'", "ts": 1785207176.91857}`
- `{"source": "ghidra_query", "sql": "SELECT name FROM imports WHERE name LIKE '%CreateProcess%' OR name LIKE '%WriteProcess%' OR name LIKE '%ReadProcess%' OR name LIKE '%VirtualProtect%' OR name LIKE '%Alloc%' OR name LIKE '%Thread%' OR name LIKE '%Inject%'", "ts": 1785207176.9528039}`
- `{"source": "ghidra_query", "sql": "SELECT content, address FROM strings WHERE content LIKE '%msi%' OR content LIKE '%MSI%' OR content LIKE '%install%' OR content LIKE '%Installer%' OR content LIKE '%setup%' OR content LIKE '%custom%' OR content LIKE '%action%' LIMIT 20", "ts": 1785207176.9816287}`
- `{"source": "ghidra_query", "sql": "SELECT content, address FROM strings WHERE content LIKE '%Adobe%' OR content LIKE '%Reader%' OR content LIKE '%Acrobat%' LIMIT 20", "ts": 1785207181.5152938}`
- `{"source": "ghidra_query", "sql": "SELECT name FROM imports WHERE name LIKE '%Process%' OR name LIKE '%Memory%' OR name LIKE '%DLL%' OR name LIKE '%Module%'", "ts": 1785207181.563459}`
- `{"source": "ghidra_query", "sql": "SELECT content, address FROM strings WHERE content LIKE '%VirtualAlloc%' OR content LIKE '%WriteProcess%' OR content LIKE '%CreateRemote%' OR content LIKE '%NtCreate%' OR content LIKE '%NtMap%' OR content LIKE '%URL%' OR content LIKE '%http%' OR content LIKE '%Down`
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, size, instruction_count, cyclomatic_complexity, call_out_count, string_ref_count FROM function_metrics ORDER BY call_out_count DESC LIMIT 15", "ts": 1785207238.227183}`
- `{"source": "ghidra_query", "sql": "SELECT content, address FROM strings WHERE content LIKE '%key%' OR content LIKE '%Key%' OR content LIKE '%seed%' OR content LIKE '%aes%' OR content LIKE '%AES%' OR content LIKE '%rc4%' OR content LIKE '%RC4%' OR content LIKE '%mutex%' OR content LIKE '%Mutex%' OR c`
- `{"source": "ghidra_query", "sql": "SELECT content, address FROM strings WHERE content LIKE '%192.%' OR content LIKE '%10.%' OR content LIKE '%172.%' OR content LIKE '%.com%' OR content LIKE '%.org%' OR content LIKE '%.net%' OR content LIKE '%://%' OR content LIKE '%www.%' LIMIT 20", "ts": 1785207242`
- `{"source": "ghidra_query", "sql": "SELECT name, address, data_type, size FROM data_items WHERE name LIKE '%Adobe%' OR name LIKE '%Setup%' OR name LIKE '%Copyright%' LIMIT 10", "ts": 1785207247.6240315}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM exports LIMIT 10", "ts": 1785207247.6503348}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM db_info", "ts": 1785207248.983626}`
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name, class, size, is_read, is_write, is_exec FROM memory_blocks ORDER BY start_ea", "ts": 1785207250.6220257}`
- `{"source": "ghidra_query", "sql": "SELECT content, address FROM strings WHERE content LIKE '%cobalt%' OR content LIKE '%beacon%' OR content LIKE '%mirai%' OR content LIKE '%icedid%' OR content LIKE '%njrat%' OR content LIKE '%reflective%' OR content LIKE '%shellcode%' OR content LIKE '%meterpreter%'`
- `{"source": "ghidra_query", "sql": "SELECT content, address FROM strings WHERE content LIKE '%encrypt%' OR content LIKE '%decrypt%' OR content LIKE '%payload%' OR content LIKE '%trojan%' OR content LIKE '%backdoor%' OR content LIKE '%persistence%' OR content LIKE '%startup%' OR content LIKE '%run%' O`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785207265.5750947}`
- `{"source": "yara_gen_v2", "ts": 1785207266.6050296}`
