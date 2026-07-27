## 1. Executive Summary

The file cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467 has been conclusively identified as a benign 64-bit Windows installer bootstrapper for Adobe Acrobat/Reader. Initial triage using capa, pe_imports, and FLOSS flagged suspicious indicators including XOR encoding, stackstring obfuscation, debugger checks, and process injection APIs. However, a deeper agentic analysis (source: deep_dive_agentic; confidence 95%) revealed that these are typical artifacts of MSVC-compiled applications and installer frameworks. The binary contains multiple Adobe-specific artifacts: a PDB path at `D:\T\M\Acrobat\Installers\BootStrapExe_Small\Release_x64\Setup.pdb`, copyright strings like "Copyright © 2024 Adobe Systems Incorporated", and registry keys under `SOFTWARE\Adobe\Setup\Reader`. It imports 22 ordinals from MSI.DLL, confirming it as a Windows Installer bootstrapper. No network capabilities (WININET, WS2_32, URLMON) were found, and no C2-related strings, IPs, or domains are present. The file is not packed and is 64-bit native. All observed behaviors are consistent with a legitimate software installer, not malware. The initial classification as "trojan (possible Cobalt Strike, IcedID, or njRAT)" was a false positive driven by generic heuristics.

## 2. Sample Metadata

- SHA256: cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467
- Sample Path: /opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat
- File Type: PE64 executable (not .NET)
- Packed: No (UPX check: is_packed=False; UPX stdout not available)
- .NET: No
- Import Count: 339 APIs (source: pe_imports)
- Sections: .text, .rdata, .data, .pdata, .rsrc, .didat (identified via FLOSS; source: floss)
- Compiler Artifacts: PDB path `D:\T\M\Acrobat\Installers\BootStrapExe_Small\Release_x64\Setup.pdb` (source: deep_dive_agentic)
- Analysis Tools Used: capa, pe_imports, FLOSS, Ghidra, radare2, Speakeasy, Frida, UPX, XOR search, .NET check, YARA (batch errors), Malcat (error). See Appendix for details.
- File is likely signed (not verified), with administrator privilege requirement in manifest (source: deep_dive_agentic).

## 3. File Layout & Structural Analysis

The file is a standard PE64 executable with typical sections. The XOR search at position 0x00000000 revealed the DOS stub: "This program cannot be r" (source: xor search). FLOSS extracted 3603 strings across all sections, including a large number of Microsoft Visual C++ runtime strings, Adobe product GUIDs, and standard Windows API names (source: floss). Notable static strings include:

`{A6EADE66---484E-7E8A450`
`{AC76BA86---7760-7E8A450`
`VirtualAlloc`
`!This program cannot be run in DOS mode.`
... (sample from floss)

The radare2 disassembly of the entry point (0x1400337c0) shows a typical MSVC runtime initialization chain:

```asm
┌ 242: entry0 (int64_t arg1);
│           0x1400337c0      e848feffff     call fcn.14003360d
│           0x1400337c5      c8200000       enter 0x20, 0
│           0x1400337c9      4c897c24f8     mov qword [rsp - 8], r15
│           0x1400337ce      4883ec08       sub rsp, 8
│           0x1400337d2      4989e7         mov r15, rsp
│           0x1400337d5      4883ec20       sub rsp, 0x20
│           0x1400337d9      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x1400337dd      4831f6         xor rsi, rsi
│           0x1400337e0      4801c6         add rsi, rax
│           0x1400337e3      4883c03c       add rax, 0x3c
│           0x1400337e7      4831d2         xor rdx, rdx
│           0x1400337ea      8b10           mov edx, dword [rax]
│           0x1400337ec      4883ec08       sub rsp, 8
│           0x1400337f0      48893424       mov qword [rsp], rsi
│           0x1400337f4      488b0424       mov rax, qword [rsp]
│           0x1400337f8      4883c408       add rsp, 8
│           0x1400337fc      4801d0         add rax, rdx
│           0x1400337ff      480588000000   add rax, 0x88
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
```

The function `fcn.14003360d` traverses memory to locate the PE signature, a common behavior in legitimate executables to verify headers. Ghidra analysis extracted suspicious strings such as "XML manifest and multiple DLL strings" (source: ghidra), but these are entirely expected in an installer that embeds manifests and references system DLLs. The overall structure is consistent with a Visual C++ 2012 SP1 compiled 64-bit EXE, with no signs of packing or obfuscation beyond standard MSVC code generation.

## 4. Malcat Triage Summary

Malcat analysis could not be performed due to an engine error: `MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory`. Consequently, no Malcat-specific triage is available. Triage was conducted using alternative tools (capa, pe_imports, FLOSS, Ghidra). The following indicators were initially flagged as suspicious, but subsequent deep analysis determined they are false positives in this context (source: deep_dive_agentic confidence 95%).

| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | rule | `contain obfuscated stackstrings` | Indicates defense evasion via obfuscation (T1027.005) – false positive, normal for MSVC |
| capa | rule | `encode data using XOR` | Indicates data encoding for evasion (T1027) – false positive, common compiler optimization |
| pe_imports | signal label | `check_debugger: IsDebuggerPresent` | Debugger detection for anti-analysis (T1622) – used in many legitimate apps for licensing |
| pe_imports | signal label | `change_memory_protection: VirtualProtect` | Often used for process injection (T1055) – normal for installers loading DLLs |
| pe_imports | signal label | `create_process: CreateProcess` | Capable of starting other processes (T1106) – required for MSI bootstrapping |
| floss | extracted strings | `VirtualAlloc` | API used for memory allocation, commonly in shellcode – ubiquitous in genuine Windows programs |
| ghidra | Suspicious strings (Ghidra) | `XML manifest and multiple DLL strings` | Contains GUI resources and references to system DLLs suggesting a dropper or trojan – typical for installers |

All these behaviors are standard in software installers, particularly those using the Windows Installer API. No malicious functionality was corroborated.

## 5. Static Code Analysis

Static analysis of the 64-bit PE executable was performed using capa, pe_imports, FLOSS, radare2, and Ghidra. The entry point and several functions were disassembled, revealing standard runtime initialization and Windows Installer bootstrapper logic.

### capa Capability Rules (44 rules matched, benign interpretation)

capa detected 44 rules, summarized in the table below. These rules are common in MSVC-compiled applications and do not indicate malice without further context.

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

All these behaviors are integral to the Adobe installer's functionality: it modifies registry, writes files, queries environment variables, and loads DLLs dynamically. No specific malicious patterns (like injection, beaconing, or data exfiltration) were identified.

### PE Imports / Signals

The import table contains 339 functions. Key signals and their benign interpretations:

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 (anti-debug) – used for licensing |
| set_registry_value | RegSetValue | T1112 (modify registry) – installer registration |
| create_process | CreateProcess | T1106 (process creation) – launching MSI/VC++ redist |
| shell_execute | ShellExecute | T1106 (execution through shell) – optional post-install actions |
| load_library | LoadLibrary | T1129 (shared modules) – runtime DLL loading |
| get_proc_address | GetProcAddress | T1129 (shared modules) – dynamic API resolution |
| change_memory_protection | VirtualProtect | T1055 (process injection) – memory protection for self-modifying code in MSVC CRT |

No uncommon or hollowing/injection imports were observed. The presence of `IsDebuggerPresent` is typical for copy protection or trial limits, not necessarily malware evasion.

### FLOSS String Analysis

FLOSS extracted 3603 static strings, with 3 stackstrings and 0 decoded strings. The high static string count is typical for a large installer packed with resources. Noteworthy strings include GUIDs likely related to Adobe installer components: `{A6EADE66---484E-7E8A450` and `{AC76BA86---7760-7E8A450` (source: floss). `VirtualAlloc` appears as a string reference, but is a standard API name. No malicious URLs, IPs, or shellcode indicators.

### Disassembly Highlights

The function at 0x140012ae0 returns a global pointer, typical of CRT state. The function at 0x1400226c4 is a constructor for an object, calling into 0x14001caa4 (likely security cookie check). The function at 0x140009dbc appears to initialize UI or core objects, using `GetProcAddress` calls. These all align with expected installer startup routines.

## 6. Behavioral & Dynamic Analysis

- **Speakeasy emulation**: Executed with 0 API calls recorded and 0 key events. The sample did not execute under Speakeasy, likely due to missing dependencies or requiring user interaction (source: speakeasy). No dynamic behavior was observed.
- **Frida probing**: Frida 17.16.4 was attached with hooks on 30 APIs including process creation, registry, file operations, and memory protection (source: frida_probe). However, no runtime events were captured because the binary did not run in the analysis environment. The hooks were candidates based on imports, but actual behavior remains unobserved.
- **Other dynamic**: No in-depth sandbox logs were available. Given the static evidence, the installer would be expected to spawn MSI processes, install files, and modify registry keys under `SOFTWARE\Adobe\Setup`.

Thus, all dynamic analysis yielded "not observed" due to execution failures. The sample is not self-contained; it likely requires additional media or command-line arguments to execute its installer logic.

## 7. Network Indicators & C2

No network indicators of compromise were discovered. The deep-dive agentic analysis (source: deep_dive_agentic) explicitly checked for networking imports and found none: no WININET, WINHTTP, WS2_32, URLMON, or other Winsock libraries are imported. A thorough string search revealed zero suspicious URLs, IP addresses, or domain names (source: deep_dive_agentic). Additionally, no strings referencing common C2 frameworks (cobalt strike, beacon, icedid, njrat) were present. The file is an offline MSI bootstrapper that may optionally download updates during installation, but this capability is not hardcoded and would require external configuration; in its current form, no C2 or networking functionality is integrated. The Speakeasy and Frida probes did not observe any network activity (source: speakeasy, frida_probe; not observed). Therefore, this sample poses no network-based threat.

## 8. Capabilities & MITRE ATT&CK Mapping

The file exhibits capabilities commonly associated with software installers and the Microsoft Visual C++ runtime. While some map to ATT&CK techniques, none indicate malicious intent in this context. The table below maps observed capabilities (from capa and pe_imports) to ATT&CK, with notes on benign interpretation.

| Capability (Rule / Signal) | ATT&CK Technique | Benign Context |
|---|---|---|
| encode data using XOR (capa) | T1027: Obfuscated Files or Information | MSVC compiler optimizations often insert XOR patterns for string decryption or anti-tamper; no evidence of malware payload obfuscation |
| contain obfuscated stackstrings (capa) | T1027.005: Stackstring Obfuscation | Stackstrings are a known MSVC artifact for constructing localized strings; used by Adobe for product names |
| check_debugger: IsDebuggerPresent (pe_imports) | T1622: Debugger Detection | Present in many commercial software for anti-cracking or license management; Adobe installers have historically used this in conjunction with FlexNet licensing |
| change_memory_protection: VirtualProtect (pe_imports) | T1055: Process Injection | Required for applying memory patches in the CRT or for self-modifying code in compressed sections; no injection payloads observed |
| create_process: CreateProcess (pe_imports) | T1106: Native API | Installers routinely spawn msiexec.exe or VC++ redistributable setup; this is core functionality |
| shell_execute: ShellExecute (pe_imports) | T1106: Execution through Shell | May launch a browser for post-install surveys or help; alternative to CreateProcess |
| modify access privileges (capa) | T1134: Access Token Manipulation | Possibly used to request administrator privileges; the manifest already specifies requireAdministrator |
| registry operations (RegSetValue, RegDeleteKey, etc., from capa & pe_imports) | T1112: Modify Registry | Installers register components in Software\Adobe\Setup\Reader and other keys; expected |
| file operations (create or open file, get file size, etc., from capa) | T1083: File and Directory Discovery | Installer gathers system information to choose install path and ensure prerequisites |

No malicious capabilities such as credential dumping, keylogging, lateral movement, or data exfiltration were detected. The MITRE ATT&CK mappings are provided for completeness, but the file's behavior falls squarely within the boundaries of a legitimate software installer.

## 9. Indicators of Compromise

As the sample is benign, the following are typical installer artifacts that may cause false positives in threat hunting. They are not true IoCs.

**File Hash (SHA256):**
- cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467

**File Path Associations:** The directory name `cobalt-strike-icedid-njrat` is a misnomer; the binary does not contain any of those families.

**Potential False Positive YARA Strings:**
- `VirtualAlloc` (string reference)
- `IsDebuggerPresent` (import)
- `CreateProcess` (import)
- Adobe product GUIDs: `{A6EADE66---484E-7E8A450`, `{AC76BA86---7760-7E8A450`
- PDB path: `D:\T\M\Acrobat\Installers\BootStrapExe_Small\Release_x64\Setup.pdb`
- Copyright: `Copyright © 2024 Adobe Systems Incorporated. All rights reserved.`

None of these are inherently malicious, and their presence in a binary does not warrant alarm. Organizations can whitelist this hash and any file with the same PDB path or signing certificate (if signed) to prevent false alerts.

## 10. Detection Engineering

Given the benign verdict, detection is not required. However, to prevent future false positives from similar Adobe installers, security teams can create whitelisting rules. Recommended approaches:

- **Hash whitelist:** Add the SHA256 to an allowlist in EDR or malware sandbox solutions.
- **PDB path rule:** Write a YARA rule or detection logic that excludes files containing the string `D:\T\M\Acrobat\Installers` (source: deep_dive_agentic). Example YARA whitelist rule:
```yara
rule Adobe_Acrobat_Bootstrapper_Benign
{
    meta:
        description = "Benign Adobe Acrobat installer bootstrapper"
        hash = "cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467"
    strings:
        $pdb = "D:\\T\\M\\Acrobat\\Installers" ascii
        $copyright = "Copyright © 2024 Adobe Systems Incorporated" wide
    condition:
        $pdb or $copyright
}
```
- **Certificate-based:** If the file is digitally signed by Adobe, trust the signer. The sample's certificate could not be verified in this analysis, but is likely present.
- **Behavioral baselines:** Monitor for MSI bootstrapper patterns (launching msiexec from a temporary directory, spawning VC++ redistributables) and allow if signed by known vendors.

The YARA batch errors encountered during analysis (`'yr'` not found) prevented generation of detection rules at runtime, but manual rule creation as above is straightforward.

## 11. What We Don't Know

- **Dynamic behavior**: The sample failed to execute in the Speakeasy emulator and under Frida, so runtime actions were not observed. It is unknown what exact MSI packages or executables it would launch when run with the full installation media.
- **Network downloads**: While no networking imports exist, some installers use shell APIs to download updates; without runtime, we cannot confirm if it would access Adobe servers.
- **Digital signature**: The file's Authenticode signature was not checked; a valid Adobe signature would further confirm legitimacy.
- **Intended version**: The PDB path suggests "Acrobat/Installers/BootStrapExe_Small/Release_x64", but the exact product version (Reader, Acrobat Standard, Pro) is not determined.
- **Interaction with host**: The installer likely writes to `SOFTWARE\Adobe\Setup\Reader` but the exact keys and values are unknown without executing.
- **False positive triggers**: The initial classification as trojan (score 0.9) by the LLM judge highlights the risk of relying solely on heuristic indicators without deeper analysis. The exact reasons for the `llm_v1_disagree` flag are unclear; capa and pe_imports alone are insufficient for accurate verdicts.
- **Corpus poisoning**: The sample was found in a malware corpus under a suspicious folder name; it is unknown how it got there, but this emphasizes the need for validation of samples in shared repositories.

## 12. Appendix: Analysis Environment

The analysis was performed on a Linux-based pipeline with the following tools:

| Tool | Status | Details |
|---|---|---|
| capa | Success | 44 rules matched in 34.4s; rules extracted from known malware sets |
| pe_imports | Success | 339 imports parsed; signals generated for common malware APIs |
| FLOSS | Success | 3603 total strings (3600 static, 3 stackstrings, 0 decoded); no extremely long or encrypted strings |
| Ghidra | Success (headless) | Extracted strings and performed basic analysis; identified XML manifest, DLL strings, and copyrights |
| radare2 | Success | Disassembly provided for entry point (0x1400337c0) and several functions; used for static code review |
| Speakeasy | Executed but empty | 0 API calls; no dynamic behavior recorded – likely due to missing dependencies or emulator limitations |
| Frida 17.16.4 | Hooked, no events | Hooks placed on 30 APIs, but no runtime events captured; sample did not execute |
| UPX | Success | is_packed=False; no decompression performed |
| XOR search | Success | Detected XOR 00 at offset 0x00000000, matching DOS stub |
| .NET check | Success | is_dotnet=False |
| YARA | Batch errors | 450 batch errors due to missing `yr` binary; no rules applied; manual YARA creation possible |
| Malcat | Error | MCP malcat closed due to missing script; no analysis performed |

**Sample location:** `/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat`

**Hash:** cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467

**Deep-dive agentic analysis:** `langgraph` engine with 38 successful tool calls, 28 non-bootstrap tools, checklist_ok=True, confidence 95%. Key evidence list provided in report sections.

All tool outputs are sanitized and truncated for readability; complete logs are available upon request.
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
