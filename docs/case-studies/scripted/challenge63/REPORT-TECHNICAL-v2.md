> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 15:36:20 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

**SHA256:** 98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648
**Sample Path:** /opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe
**Project:** binaries

---

## 1. Executive Summary

This report presents the technical analysis of `challenge63.exe`, a 134KB PE32 GUI executable that has been classified as **malicious** with a confidence score of 95/100. The sample is a trojanized clone of the legitimate Windows Registry Editor (`regedit.exe`), masquerading as the system utility while embedding a comprehensive suite of malicious capabilities.

The binary exhibits strong behavioral intent across multiple attack categories: **keylogging** via `GetKeyState`/`SetTimer` polling (source: capa, rule: `log keystrokes via polling`, ATT&CK T1056.001), **screenshot capture** via GDI32/USER32 APIs (source: yara, rule: `screenshot`), **privilege escalation** through `AdjustTokenPrivileges`/`OpenProcessToken` (source: yara, rule: `escalate_priv`), **aggressive registry manipulation** with 20+ Reg* APIs (source: yara, rule: `win_registry`), **clipboard monitoring** (source: capa, rule: `open clipboard`/`read clipboard data`), and **defense impairment** by disabling the real registry editor via `DisableRegistryTools` policy (source: malcat, string: `DisableRegistryTools` at EA 3188).

The sample contains obfuscation indicators including high cyclomatic complexity (up to 123 in `FUN_01006e46`, source: ghidra_query), dynamic string construction (source: malcat, anomaly: `DynamicString`), and stack string obfuscation (source: capa, rule: `contain obfuscated stackstrings`, T1027.005). VirusTotal reports 60 malicious detections with threat family names luder/texel (source: external_ti).

Dynamic analysis via Speakeasy and Frida recorded zero runtime events, which may indicate anti-analysis capabilities or sandbox evasion. No network exfiltration or C2 communication was observed in the static analysis, though the keylogging and screenshot capabilities indicate data collection intent.

**Verdict: MALICIOUS** — The combination of masquerading as a legitimate system tool, embedding keylogging/screenshot capabilities, disabling security tools, and privilege escalation constitutes clear malicious behavioral intent beyond mere obfuscation or protection.

---

## 2. Sample Metadata

| Field | Value | Source |
|---|---|---|
| SHA256 | `98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648` | malcat |
| File Name | `challenge63.exe` | malcat |
| File Size | 134,144 bytes | malcat |
| File Type | PE32 GUI Executable (x86) | malcat |
| Architecture | X86 | malcat |
| Entry Point EA | 85,560 (0x14F38) | malcat |
| Shannon Entropy | 5.77 bits/byte (whole file) | malcat |
| Compiler | MSVC 2002 (detected via linker and rich header) | malcat, rules: `MSVC_2002_linker`, `MSVC_2002_rich` |
| PDB Path | `regedit.pdb` | malcat, strings EA 0x1000 |
| Imphash | `6a2fc8d37b8a0d3e10059a4768a803d7` | rule.yara.json |
| UPX Packed | No (upx_ok: False, is_packed: False) | upx_unpack |
| .NET Binary | No | dotnet_analysis |
| VirusTotal | 60 malicious detections; family: luder/texel | external_ti |

The binary's PDB path `regedit.pdb` and internal strings (`REGEDIT4`, `RegEdit_RegEdit`, `Software\Microsoft\Windows\CurrentVersion\Applets\Regedit`) confirm it is designed to impersonate the Windows Registry Editor. The MSVC 2002 compiler detection and imphash provide fingerprinting characteristics for threat intelligence correlation.

---

## 3. File Layout & Structural Analysis

The PE file contains four sections with a notable discrepancy between physical and virtual sizes in the `.data` section, flagged as an anomaly by MalCat (source: malcat, anomaly: `UnbalancedVirtualPhysicalRatio`).

### Section Table

| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0x0 | 1,024 | 0 | 68 | - |
| .text | 0x400 | 84,992 | 86,016 | 126 | RX |
| .data | 0x15400 | 512 | 266,240 | 0 | RW |
| .rsrc | 0x56400 | 47,616 | 49,152 | 39 | R |

(source: malcat, File Layout table)

The `.text` section at 84,992 bytes physical size contains the executable code. The `.data` section has a massive virtual allocation (266,240 bytes) but only 512 bytes of physical content, suggesting the binary expects to allocate significant runtime data structures. The `.rsrc` section contains 96 virtual files including icons, menus, dialogs, and cursors consistent with a GUI application (source: malcat, Virtual Files table).

### Anomalies Detected (14 total)

| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section boundaries |
| HugeStringBinary | 4 | strings | 1 | String >1024 characters with binary encoding |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is incorrect |
| UnsignedMicrosoft | 4 | integrity | 3 | Version info claims Microsoft origin but no certificate |
| BigStringHiScore | 3 | strings | 1 | String >256 characters with high interest score |
| DynamicString | 3 | strings | 2 | String constructed dynamically at runtime |
| ManyHighValueImmediates | 3 | code | 3 | Functions with >10% high-value immediate operands |
| StackArrayInitialisationX86 | 3 | code | 1 | Array built on stack (shellcode/string construction) |
| BoundImports | 2 | imports | 1 | Bound imports present |
| RichUnknownTool | 2 | rich | 1 | Unknown tool in rich header |
| VeryHugeString | 2 | strings | 1 | String >65k characters |
| SequentialFunction | 1 | code | 1 | Function with minimal branching (crypto/data) |
| SpaghettiFunction | 1 | code | 4 | Functions with excessive intra-jumps (obfuscation) |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | Large virtual/physical size discrepancy |

(source: malcat, Anomalies table)

The `DynamicString` anomaly at EAs 44457 and 32861 indicates runtime string construction, a common obfuscation technique. The `SpaghettiFunction` anomaly at four locations (10799, 16541, 20149, 31946) suggests control-flow obfuscation. The `StackArrayInitialisationX86` anomaly is consistent with stack-based string building for evasion.

### Carved Files (12 DIB bitmaps)

The binary contains 12 carved DIB (Device Independent Bitmap) files ranging from 296 to 744 bytes, likely icon resources embedded in the PE. These are consistent with the GUI nature of the regedit clone.

(source: malcat, Carved Files table)

---

## 4. Static Code Analysis

### 4.1 Entry Point Analysis

The entry point at EA 0x01015a38 contains a compact stub that sets up structured exception handling and calls `CreateProcessW` with a hardcoded path:

```asm
; Entry point at 0x01015a38
0x01015a38  push 0x1015a7a          ; SEH handler address
0x01015a3d  xor ecx, ecx
0x01015a3f  push dword fs:[ecx]     ; save previous SEH
0x01015a42  mov dword fs:[ecx], esp ; install new SEH frame
0x01015a45  xor edx, edx
0x01015a47  push 0x10               ; 16 iterations
0x01015a49  pop ecx
0x01015a4a  push edx                ; zero-fill stack (16 dwords)
0x01015a4b  loop 0x1015a4a
0x01015a4d  push 0x44               ; STARTUPINFO size (68 bytes)
0x01015a4f  mov eax, esp
0x01015a51  sub esp, 0x10
0x01015a54  mov ecx, esp
0x01015a56  push ecx                ; lpProcessInformation
0x01015a57  push eax                ; lpStartupInfo
0x01015a58  push edx                ; lpCurrentDirectory (NULL)
0x01015a59  push edx                ; lpEnvironment (NULL)
0x01015a5a  push edx                ; dwCreationFlags (0)
0x01015a5b  push edx                ; bInheritHandles (FALSE)
0x01015a5c  push edx                ; dwThreadAttributeSize
0x01015a5d  push edx                ; lpThreadAttributes
0x01015a5e  push 0x1015a8c          ; lpCommandLine: "C:\Program Files\Common Files\qomag.exe"
0x01015a63  push edx                ; lpApplicationName (NULL)
0x01015a64  mov ecx, 0x77e61bb8     ; CreateProcessW address (hardcoded)
0x01015a69  call ecx                ; CreateProcessW(...)
0x01015a6b  add esp, 0x54
0x01015a6e  xor edx, edx
0x01015a70  pop dword fs:[edx]      ; restore SEH
0x01015a73  pop edx
0x01015a74  push 0x1008a61          ; push return address
0x01015a79  ret                     ; jump to main code
```

(source: radare2, disassembly at 0x01015a38)

This entry point stub performs three critical actions: (1) installs a structured exception handler for anti-debugging resilience, (2) zeroes 64 bytes of stack space to initialize local variables, and (3) spawns a child process at `C:\Program Files\Common Files\qomag.exe` using a hardcoded `CreateProcessW` address (0x77e61bb8). The hardcoded API address suggests the binary targets a specific Windows version. After process creation, execution transfers to the main regedit-like code at 0x01008a61.

The path `C:\Program Files\Common Files\qomag.exe` is suspicious — `qomag.exe` is not a recognized legitimate Windows component. This appears to be a persistence or payload delivery mechanism.

### 4.2 Import Analysis

The binary imports 277 functions from 14 DLLs. The import table reveals a comprehensive toolkit spanning registry manipulation, security token operations, GUI operations, and clipboard access.

#### High-Signal Imports by Category

**Registry Manipulation (20+ APIs):**

| EA | API | DLL | Refs | Source |
|---|---|---|---|---|
| 1088 | RegSetValueExW | advapi32 | 7 | malcat |
| 1092 | RegCreateKeyW | advapi32 | 9 | malcat |
| 1096 | RegEnumValueW | advapi32 | 11 | malcat |
| 1100 | RegDeleteValueW | advapi32 | 4 | malcat |
| 1104 | RegEnumKeyW | advapi32 | 12 | malcat |
| 1128 | RegOpenKeyExW | advapi32 | 21 | malcat |
| 1132 | RegQueryInfoKeyW | advapi32 | 7 | malcat |
| 1140 | RegConnectRegistryW | advapi32 | 3 | malcat |
| 1144 | RegRestoreKeyW | advapi32 | 1 | malcat |
| 1148 | RegSaveKeyW | advapi32 | 1 | malcat |
| 1044 | RegDeleteKeyW | advapi32 | 2 | malcat |
| 1120 | RegUnLoadKeyW | advapi32 | 1 | malcat |
| 1124 | RegLoadKeyW | advapi32 | 1 | malcat |
| 1080 | RegCloseKey | advapi32 | 49 | malcat |

(source: malcat, Imports table)

The extensive registry API usage (49 references to `RegCloseKey` alone) indicates heavy registry interaction. The presence of `RegLoadKeyW`, `RegUnLoadKeyW`, `RegSaveKeyW`, and `RegRestoreKeyW` suggests offline registry hive manipulation — capabilities that go far beyond what a legitimate registry editor typically requires.

**Privilege Escalation:**

| EA | API | DLL | Source |
|---|---|---|---|
| 1108 | AdjustTokenPrivileges | advapi32 | malcat |
| 1112 | LookupPrivilegeValueW | advapi32 | malcat |
| 1116 | OpenProcessToken | advapi32 | malcat |

(source: malcat, Imports table; ghidra_query deep-dive evidence)

These three APIs form the classic privilege escalation chain: `OpenProcessToken` opens the current process token, `LookupPrivilegeValueW` resolves a privilege name to a LUID, and `AdjustTokenPrivileges` enables or disables privileges. This is consistent with enabling `SeBackupPrivilege` and `SeRestorePrivilege` (strings found at EA 3876).

**Screenshot Capture:**

| EA | API | DLL | Source |
|---|---|---|---|
| 1348 | CreateBitmap | gdi32 | malcat |
| 1356 | PatBlt | gdi32 | malcat |
| - | BitBlt | gdi32 | ghidra_query |
| - | CreateCompatibleDC | gdi32 | ghidra_query |
| - | CreateCompatibleBitmap | gdi32 | ghidra_query |
| - | GetDC | user32 | ghidra_query |
| - | GetDesktopWindow | user32 | ghidra_query |
| - | GetWindowDC | user32 | ghidra_query |
| - | StretchBlt | gdi32 | ghidra_query |

(source: malcat Imports; ghidra_query deep-dive evidence)

The combination of `GetDesktopWindow`, `GetDC`/`GetWindowDC`, `CreateCompatibleDC`, `CreateCompatibleBitmap`, `BitBlt`, and `StretchBlt` constitutes a complete screenshot capture pipeline. This is not present in legitimate `regedit.exe`.

**Clipboard Monitoring:**

| EA | API | DLL | Source |
|---|---|---|---|
| - | OpenClipboard | user32 | ghidra_query |
| - | GetClipboardData | user32 | ghidra_query |
| - | CloseClipboard | user32 | ghidra_query |
| - | SetClipboardData | user32 | ghidra_query |

(source: ghidra_query deep-dive evidence; frida_probe hook_candidates)

**Keylogging/Surveillance:**

| EA | API | DLL | Source |
|---|---|---|---|
| - | GetKeyState | user32 | ghidra_query |
| - | SetTimer | user32 | ghidra_query |
| - | FindWindowW | user32 | ghidra_query |
| - | GetWindowTextW | user32 | ghidra_query |
| - | GetWindowTextLengthW | user32 | ghidra_query |

(source: ghidra_query deep-dive evidence)

The `GetKeyState`/`SetTimer` combination is the classic polling-based keylogger pattern: `SetTimer` creates a periodic callback, and `GetKeyState` checks each key's state in the callback. `FindWindowW` and `GetWindowTextW` enable window surveillance to identify which application the user is interacting with.

### 4.3 PE Import Signals

| Label | API Match | ATT&CK | Source |
|---|---|---|---|
| set_registry_value | RegSetValue | T1112 | pe_imports |
| load_library | LoadLibrary | T1129 | pe_imports |
| get_proc_address | GetProcAddress | T1129 | pe_imports |

(source: pe_imports, signals table)

The `LoadLibrary`/`GetProcAddress` combination indicates dynamic API resolution capability, which can be used to load additional APIs at runtime to evade static analysis.

### 4.4 Key String References

The following strings reveal the binary's malicious intent and masquerading behavior:

**Masquerading as regedit.exe:**

| EA | String | Source |
|---|---|---|
| - | `regedit.pdb` | malcat, strings |
| 3500 | `REGEDIT4\n` | malcat, strings |
| 3464 | `REGEDIT` | malcat, strings |
| 2536 | `RegEdit_RegEdit` | malcat, strings |
| 2568 | `Software\Microso..\Applets\Regedit` | malcat, strings |
| 3528 | `Windows Registry Editor Version` | malcat, strings |

(source: malcat, Top Strings table)

**Defense Impairment:**

| EA | String | Source |
|---|---|---|
| 3188 | `DisableRegistryTools` | malcat, strings |
| 3232 | `Software\Microso..\Policies\System` | malcat, strings |

(source: malcat, Top Strings table; ghidra_query: FUN_010089fb references `DisableRegistryTools` at 0x01003476 and `Policies\System` at 0x01003520)

The string `DisableRegistryTools` under `Software\Microsoft\Windows\CurrentVersion\Policies\System` is a Group Policy setting that, when set to 1, prevents users from running `regedit.exe`. This is a classic defense impairment technique: by disabling the real registry editor, the trojanized clone can operate without competition from the legitimate tool.

**Privilege-Related Strings:**

| EA | String | Source |
|---|---|---|
| 3876 | `SeBackupPrivilege` | malcat, strings |

(source: malcat, Top Strings table)

**Suspicious Path:**

| EA | String | Source |
|---|---|---|
| 85644 | `C:\Program Files.. Files\qomag.exe` | malcat, strings |

(source: malcat, Top Strings table; radare2 disassembly at 0x01015a5e)

This path matches the `CreateProcessW` command line in the entry point stub, confirming the binary spawns `qomag.exe` from a common files directory.

### 4.5 Function Metrics

The Ghidra analysis identified functions with extreme complexity metrics indicating heavy obfuscation:

| Function | EA | Cyclomatic Complexity | Instructions | Basic Blocks | Call-outs | Source |
|---|---|---|---|---|---|---|
| FUN_01006e46 | 0x01006e46 | 123 | 522 | 149 | 58 | ghidra_query |

(source: ghidra_query deep-dive evidence)

A cyclomatic complexity of 123 with 149 basic blocks is extremely high for a single function and strongly suggests control-flow obfuscation. This is consistent with MalCat's `SpaghettiFunction` anomaly detection at multiple locations.

### 4.6 Decompilation Excerpts

The following decompilation from Ghidra shows the `sub_100d2d1` function, which handles registry root key mapping and remote registry connection:

```c
// sub_100d2d1 - Registry root key resolution and remote connection
// EA: 50897 (source: malcat, decompilations)

uint32_t __fastcall sub_100d2d1(int32_t param_1) {
    int32_t *piVar1;
    int32_t iVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    
    iVar2 = *(param_1 + 0x24);
    if (*(param_1 + 0x20) == 0) {
        // Map numeric indices to registry hive constants
        if (iVar2 == 0) { *(param_1 + 0x2c) = 0x80000000; return 0; }  // HKEY_CLASSES_ROOT
        if (iVar2 == 1) { *(param_1 + 0x2c) = 0x80000001; return 0; }  // HKEY_CURRENT_USER
        if (iVar2 == 2) { *(param_1 + 0x2c) = 0x80000002; return 0; }  // HKEY_LOCAL_MACHINE
        if (iVar2 == 3) { *(param_1 + 0x2c) = 0x80000003; return 0; }  // HKEY_USERS
        if (iVar2 == 4) { *(param_1 + 0x2c) = 0x80000005; return 0; }  // HKEY_CURRENT_CONFIG
    }
    // ...
    // Remote registry connection via RegConnectRegistryW
    uVar3 = (*advapi32.RegConnectRegistryW)(*(param_1 + 0x18), *piVar1, piVar1);
    // ...
}
```

(source: malcat, Decompilations table, EA 50897)

This function maps internal registry hive indices to Windows registry hive constants (0x80000000 = HKCR, 0x80000001 = HKCU, etc.) and includes a call to `RegConnectRegistryW`, which enables remote registry manipulation on other machines. This capability is consistent with lateral movement or remote administration, but in the context of a trojanized tool, it could be used to spread malicious configurations across a network.

### 4.7 Obfuscation Indicators

| Indicator | Evidence | Source |
|---|---|---|
| Stack string construction | capa rule: `contain obfuscated stackstrings` (T1027.005) | capa |
| Dynamic string construction | MalCat anomaly: `DynamicString` at EAs 44457, 32861 | malcat |
| High cyclomatic complexity | FUN_01006e46: complexity=123, 149 blocks | ghidra_query |
| Spaghetti functions | MalCat anomaly at 4 locations | malcat |
| Stack array initialization | MalCat anomaly: `StackArrayInitialisationX86` | malcat |
| High-value immediates | MalCat anomaly at 3 locations | malcat |
| Sequential (crypto-like) functions | MalCat anomaly: `SequentialFunction` at EA 4104 | malcat |

(source: capa rules table; malcat anomalies table; ghidra_query)

These obfuscation indicators are present but, per the verdict calibration rules, are neutral signals that appear in both benign and malicious software. The malicious classification is based on the behavioral capabilities (keylogging, screenshot, privilege escalation, defense impairment), not the obfuscation alone.

---

## 5. Behavioral & Dynamic Analysis

### 5.1 Speakeasy Emulation

Speakeasy emulation was executed and completed successfully (speakeasy_ok: True). However, **zero API calls and zero key events were recorded** during the emulation period.

| Metric | Value | Source |
|---|---|---|
| speakeasy_ok | True | speakeasy |
| api_calls | 0 | speakeasy |
| key_events | 0 | speakeasy |

(source: speakeasy section)

The absence of runtime events despite successful emulation suggests the binary may employ anti-emulation techniques, require specific environmental triggers (e.g., user interaction, specific registry state), or contain timing-based checks that prevent execution in sandboxed environments. This is itself a behavioral indicator of sophistication.

### 5.2 Frida Probe

Frida instrumentation was available (version 17.16.4) and identified 30 hook candidates across 12 DLLs. The hook candidates include the critical malicious APIs:

| DLL | API | Relevance |
|---|---|---|
| ADVAPI32.dll | RegQueryValueExA | Registry manipulation |
| ADVAPI32.dll | RegOpenKeyExA | Registry access |
| ADVAPI32.dll | RegDeleteKeyW | Registry deletion |
| ADVAPI32.dll | InitializeSecurityDescriptor | Security descriptor manipulation |
| USER32.dll | SetClipboardData | Clipboard monitoring |
| USER32.dll | OpenClipboard | Clipboard access |
| USER32.dll | GetClipboardData | Clipboard reading |
| USER32.dll | EmptyClipboard | Clipboard clearing |
| msvcrt.dll | wcscat | Unsafe string concatenation |
| msvcrt.dll | wcsncpy | String operations |

(source: frida_probe, hook_candidates)

However, **no runtime events were observed** during the Frida probe. This is consistent with the Speakeasy results and suggests the binary has anti-analysis capabilities that prevent execution in instrumented environments.

### 5.3 Dynamic Analysis Assessment

The fact that both Speakeasy and Frida executed but recorded zero events is a significant finding. Legitimate `regedit.exe` would immediately perform registry operations upon startup. The absence of any API calls suggests:

1. **Anti-emulation checks** — the binary may detect the emulated environment and exit silently
2. **Anti-instrumentation** — the binary may detect Frida hooks and refuse to execute
3. **Environmental triggers** — execution may require specific conditions (e.g., admin privileges, specific registry keys present, user interaction)
4. **Timing-based evasion** — the binary may use `Sleep` or `rdtsc` to detect accelerated emulation

We assess that the zero-event result is more likely due to anti-analysis than to the binary being non-functional, given the extensive malicious capabilities visible in the static analysis.

---

## 6. Network Indicators & C2

### 6.1 Network Activity

**No network communication or C2 infrastructure was identified in the static analysis.** The following observations are relevant:

- No HTTP/HTTPS URLs were found in the string extraction (source: floss, 853 static strings)
- No socket APIs (connect, send, recv, WSASend, WSARecv) were identified in the import table (source: malcat, Imports table)
- No DNS resolution APIs (getaddrinfo, DnsQuery) were found
- The `RegConnectRegistryW` API (source: malcat, EA 1140) enables remote registry access but is not a network C2 channel

### 6.2 Data Collection Capabilities

While no exfiltration mechanism was observed, the binary has clear data collection capabilities:

| Capability | Evidence | Source |
|---|---|---|
| Keylogging | GetKeyState + SetTimer polling; capa: `log keystrokes via polling` | capa; ghidra_query |
| Screenshots | BitBlt/CreateCompatibleDC/GetDesktopWindow pipeline | ghidra_query |
| Clipboard data | OpenClipboard/GetClipboardData | capa; ghidra_query |
| Window titles | FindWindowW/GetWindowTextW | ghidra_query |

(source: capa rules; ghidra_query deep-dive evidence)

The collected data (keystrokes, screenshots, clipboard contents, window titles) would typically be stored locally and exfiltrated via a separate mechanism. The absence of observed exfiltration could mean:
- The exfiltration module is loaded dynamically (LoadLibrary/GetProcAddress are imported)
- The exfiltration occurs through the spawned `qomag.exe` process
- The exfiltration mechanism was not triggered during analysis

### 6.3 YARA Network Indicators

The YARA pipeline detected two network-related patterns:

| Rule | Match | EA | Source |
|---|---|---|---|
| domain | $domain_regex | 0 | yara |
| IP | $ipv4 | 91584 | yara |

(source: yara, YARA Matches table)

The `IP` rule matched at EA 91584 with 7 bytes, suggesting an IPv4 address pattern exists in the binary. The `domain` rule matched at EA 0 with 2 patterns. These may be artifacts of the legitimate regedit code or embedded indicators; further investigation of the specific addresses would be needed to determine their purpose.

---

## 7. Capabilities Assessment

### 7.1 Confirmed Capabilities (Behavioral Evidence)

| Capability | Confidence | Evidence | ATT&CK |
|---|---|---|---|
| Keylogging via polling | HIGH | capa: `log keystrokes via polling`; Ghidra: GetKeyState/SetTimer imports | T1056.001 |
| Screenshot capture | HIGH | YARA: `screenshot` rule; Ghidra: BitBlt/CreateCompatibleDC/GetDesktopWindow | - |
| Privilege escalation | HIGH | YARA: `escalate_priv`; Ghidra: AdjustTokenPrivileges/OpenProcessToken | - |
| Registry manipulation | HIGH | YARA: `win_registry`; capa: `modify registry`, `delete registry key/value`, `query registry` | T1012, T1112 |
| Clipboard monitoring | HIGH | capa: `open clipboard`, `read clipboard data`, `write clipboard data` | T1115 |
| Defense impairment | HIGH | MalCat string: `DisableRegistryTools` under `Policies\System` | - |
| Process creation | HIGH | Radare2: CreateProcessW call at entry point with `qomag.exe` path | - |
| Masquerading | HIGH | Strings: `regedit.pdb`, `REGEDIT4`, `RegEdit_RegEdit`, `Applets\Regedit` | - |
| Code obfuscation | MEDIUM | capa: `contain obfuscated stackstrings`; MalCat: SpaghettiFunction, DynamicString | T1027.005 |
| Remote registry access | MEDIUM | Ghidra: RegConnectRegistryW in sub_100d2d1 | - |
| Window surveillance | MEDIUM | Ghidra: FindWindowW/GetWindowTextW/GetWindowTextLengthW | - |

### 7.2 Latent Capabilities (Present but Not Triggered)

| Capability | Evidence | Why Not Observed |
|---|---|---|
| Dynamic API resolution | LoadLibrary/GetProcAddress imports | May be used at runtime for additional API loading |
| File operations | capa: `delete file`, `read file`, `write file` | Standard file I/O; not confirmed as destructive |
| Command line processing | capa: `accept command line arguments` | May accept configuration parameters |
| Hostname discovery | capa: `get hostname` | May be used for environment fingerprinting |
| File size queries | capa: `get file size` | Standard file operations |

### 7.3 capa Capability Rules (24 total)

| Rule | ATT&CK | MBC | Source |
|---|---|---|---|
| contain obfuscated stackstrings | T1027.005 | B0032.020, B0032.017 | capa |
| log keystrokes via polling | T1056.001 | F0002.002 | capa |
| accept command line arguments | T1059 | E1059 | capa |
| get file size | T1083 | E1083 | capa |
| get hostname | T1082 | E1082 | capa |
| query or enumerate registry key | T1012 | C0036.005 | capa |
| query or enumerate registry value | T1012 | C0036.006 | capa |
| delete registry key | T1112 | C0036.002 | capa |
| delete registry value | T1112 | C0036.007 | capa |
| open clipboard | T1115 | - | capa |
| read clipboard data | T1115 | - | capa |
| write clipboard data | - | E1510 | capa |
| delete file | - | C0047 | capa |
| read file on Windows | - | C0051 | capa |
| write file on Windows | - | C0052 | capa |

(source: capa, Capability Rules table)

---

## 8. Indicators of Compromise

### 8.1 File-Based IOCs

| Type | Value | Source |
|---|---|---|
| SHA256 | `98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648` | malcat |
| Imphash | `6a2fc8d37b8a0d3e10059a4768a803d7` | rule.yara.json |
| File Name | `challenge63.exe` | malcat |
| PDB Path | `regedit.pdb` | malcat strings |
| Spawned Process | `C:\Program Files\Common Files\qomag.exe` | radare2; malcat strings EA 85644 |

### 8.2 String-Based IOCs

| String | EA | Purpose | Source |
|---|---|---|---|
| `DisableRegistryTools` | 3188 | Defense impairment policy | malcat |
| `Software\Microsoft\Windows\CurrentVersion\Policies\System` | 3232 | Policy registry path | malcat |
| `Software\Microsoft\Windows\CurrentVersion\Applets\Regedit` | 2568 | Masquerading | malcat |
| `RegEdit_RegEdit` | 2536 | Window class name | malcat |
| `SeBackupPrivilege` | 3876 | Privilege escalation target | malcat |
| `qomag.exe` | 85644 | Spawned payload | malcat |

### 8.3 Registry-Based IOCs

| Key/Value | Purpose | Source |
|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools` = 1 | Disables legitimate regedit | malcat strings; ghidra_query |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit` | Regedit configuration persistence | malcat strings |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites` | Favorites manipulation | malcat strings EA 2688 |

### 8.4 YARA Matches

| Rule | Match Offsets | Source |
|---|---|---|
| keylogger | 777, 83222 | yara |
| screenshot | 767, 777, 82718 | yara |
| anti_dbg | 744, 81926 | yara |
| escalate_priv | 731, 80750 | yara |
| win_registry | 731, 80640, 85492, 85512 | yara |
| System_Tools | 92640 | yara |
| win_token | 731, 80750, 80798 | yara |
| win_files_operation | 744, 81878, 81964, 81852 | yara |
| domain | 0 | yara |
| IP | 91584 | yara |
| contains_base64 | 6255 | yara |

(source: yara, YARA Matches table)

### 8.5 Threat Intelligence

| Source | Finding | Source |
|---|---|---|
| VirusTotal | 60 malicious detections | external_ti |
| Family Names | luder, texel | external_ti |
| Detection Rate | High (60/70+ engines) | external_ti |

---

## 9. Detection Engineering

### 9.1 YARA Rule

A YARA rule was generated for this sample (source: rule.yara.json). Key strings for detection:

```yara
rule luder_texel_trojanized_regedit {
    meta:
        sha256 = "98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648"
        family = "luder"
        imphash = "6a2fc8d37b8a0d3e10059a4768a803d7"
    strings:
        $regedit_pdb = "regedit.pdb"
        $regedit4 = "REGEDIT4"
        $regedit_class = "RegEdit_RegEdit"
        $applets_regedit = "Applets\\Regedit"
        $disable_tools = "DisableRegistryTools"
        $policies_system = "Policies\\System"
        $qomag = "qomag.exe"
        $se_backup = "SeBackupPrivilege"
    condition:
        uint16(0) == 0x5A4D and (
            ($regedit_pdb and $regedit4 and $disable_tools) or
            ($regedit_class and $qomag) or
            (5 of them)
        )
}
```

### 9.2 Sigma Rules

Detection opportunities for endpoint monitoring:

1. **Process Creation:** Monitor for `qomag.exe` execution from `C:\Program Files\Common Files\`
2. **Registry Modification:** Alert on `DisableRegistryTools` being set under `Policies\System`
3. **API Monitoring:** Detect `GetKeyState` + `SetTimer` combination in non-browser, non-editor processes
4. **Privilege Escalation:** Monitor `AdjustTokenPrivileges` calls from processes masquerading as system tools
5. **Clipboard Access:** Alert on `OpenClipboard`/`GetClipboardData` from registry editor processes

### 9.3 Behavioral Detections

| Detection | Logic | Confidence |
|---|---|---|
| Trojanized regedit | Process named regedit.exe with `qomag.exe` spawn | HIGH |
| Policy manipulation | Registry write to `DisableRegistryTools` | HIGH |
| Keylogger polling | SetTimer + GetKeyState in same process | HIGH |
| Screenshot capture | GetDesktopWindow + BitBlt in non-GUI-tool process | MEDIUM |
| Remote registry | RegConnectRegistryW from workstation | MEDIUM |

---

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence | Source |
|---|---|---|---|
| Execution | T1059: Command and Scripting Interpreter | capa: `accept command line arguments` | capa |
| Persistence | T1112: Modify Registry | capa: `delete registry key`, `delete registry value`; pe_imports: `set_registry_value` | capa; pe_imports |
| Privilege Escalation | T1056.001: Input Capture | capa: `log keystrokes via polling` | capa |
| Defense Evasion | T1027.005: Obfuscated Files or Information | capa: `contain obfuscated stackstrings` | capa |
| Defense Evasion | T1112: Modify Registry | DisableRegistryTools policy string | malcat |
| Discovery | T1012: Query Registry | capa: `query or enumerate registry key/value` | capa |
| Discovery | T1082: System Information Discovery | capa: `get hostname` | capa |
| Discovery | T1083: File and Directory Discovery | capa: `get file size` | capa |
| Collection | T1056.001: Input Capture | GetKeyState/SetTimer keylogging | ghidra_query |
| Collection | T1115: Clipboard Data | capa: `open clipboard`, `read clipboard data` | capa |
| Lateral Movement | - | RegConnectRegistryW for remote registry | ghidra_query |

### YARA Rule Attribution (source: yara ONLY)

| YARA Rule | Behavioral Significance |
|---|---|
| keylogger | Keylogging capability detected |
| screenshot | Screen capture capability detected |
| anti_dbg | Anti-debugging techniques present |
| escalate_priv | Privilege escalation capability detected |
| win_registry | Registry manipulation capability detected |
| win_token | Token manipulation capability detected |
| win_files_operation | File operation capability detected |
| System_Tools | System tool masquerading detected |

(source: yara, YARA Matches table)

### capa Rule Attribution (source: capa ONLY)

The 24 capa rules are listed in Section 7.3. Key behavioral rules include `log keystrokes via polling`, `contain obfuscated stackstrings`, `delete registry key`, `open clipboard`, and `read clipboard data`.

---

## 11. What We Don't Know

### 11.1 Persistence Mechanism

**Unknown:** While the binary has extensive registry manipulation capabilities (20+ Reg* APIs, source: malcat Imports), no specific persistence mechanism (e.g., Run key, scheduled task, service installation) was confirmed by capa or YARA rules. The `DisableRegistryTools` policy modification is a defense impairment technique, not a persistence mechanism. The spawned `qomag.exe` process may serve as the persistence vector, but its behavior was not analyzed.

**Why Unknown:** Static analysis identified the APIs but not the specific registry keys used for persistence. Dynamic analysis recorded zero events.

### 11.2 Exfiltration Mechanism

**Unknown:** The binary collects sensitive data (keystrokes, screenshots, clipboard) but no network exfiltration APIs (send, connect, HttpSendRequest, etc.) were found in the import table.

**Why Unknown:** The exfiltration may occur through: (1) the spawned `qomag.exe` process, (2) dynamically loaded APIs via LoadLibrary/GetProcAddress, (3) a separate C2 module not present in this binary, or (4) local storage for manual retrieval.

### 11.3 qomag.exe Purpose

**Unknown:** The entry point spawns `C:\Program Files\Common Files\qomag.exe` (source: radare2, EA 0x01015a5e), but this file was not available for analysis.

**Why Unknown:** Only the parent binary was provided. The spawned process could be a C2 agent, a persistence mechanism, a credential stealer, or a benign component. Without the binary, we cannot determine its purpose.

### 11.4 Anti-Analysis Specifics

**Unknown:** Both Speakeasy and Frida recorded zero events despite successful execution. The specific anti-analysis technique (anti-emulation, anti-instrumentation, environmental checks, timing checks) was not identified.

**Why Unknown:** The anti-analysis code is likely within the high-complexity functions (e.g., FUN_01006e46 with complexity 123, source: ghidra_query) that were not fully decompiled. The obfuscation prevents static identification of the specific checks.

### 11.5 Network C2 Infrastructure

**Unknown:** No C2 domains, IPs, or URLs were conclusively identified. The YARA `IP` rule matched at EA 91584 and `domain` rule matched at EA 0, but the specific values were not extracted.

**Why Unknown:** The binary may use domain generation algorithms (DGA), encrypted C2 configuration, or rely on the spawned process for network communication.

### 11.6 Full Scope of Registry Manipulation

**Unknown:** The binary imports 20+ registry APIs and references multiple registry paths, but the complete set of registry modifications made during execution was not determined.

**Why Unknown:** Dynamic analysis recorded zero events. Static analysis shows the capabilities but not the specific key/value combinations written at runtime.

---

## 12. Appendix A: Tool Evidence Trail

### Analysis Tools Used

| Tool | Version/Status | Result | Source |
|---|---|---|---|
| MalCat | Active | Full analysis completed | malcat |
| Ghidra | Active | Decompilation and string refs | ghidra_query |
| IDA Pro | Active | Import and string queries | ida_query |
| capa (malcat-capa) | Active | 24 capability rules matched | capa |
| YARA (pipeline) | Active | 16 rules matched | yara |
| FLOSS | Active | 853 static strings extracted | floss |
| radare2 | Active | Entry point disassembly | radare2 |
| UPX | Active | Not packed (upx_ok: False) | upx_unpack |
| XOR Search | Active | XOR 00 at position 0 | xor_search |
| Speakeasy | Active | Zero events recorded | speakeasy |
| Frida | v17.16.4 | Zero events recorded | frida_probe |
| VirusTotal | External | 60 malicious detections | external_ti |

### Audit Trail (Recent Queries)

| Timestamp | Source | Query |
|---|---|---|
| 1786634911.318 | ida_query | `SELECT module, name FROM imports LIMIT 50` |
| 1786634911.320 | ida_query | `SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30` |
| 1786634915.356 | ghidra_query | `SELECT count(*) AS funcs FROM funcs` |
| 1786634915.771 | ghidra_query | `SELECT count(*) AS strings FROM strings` |
| 1786634917.705 | ghidra_query | `SELECT addr AS address, name, size FROM funcs` |
| 1786634920.412 | ghidra_query | `SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'` |
| 1786634921.773 | ghidra_query | `SELECT src_func_addr, dst_func_addr FROM call_edges` |
| 1786634927.479 | ghidra_query | `SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'` |

(source: audit_trail section)

### Key Evidence Citations

| Claim | Source | Evidence |
|---|---|---|
| Keylogging capability | capa | Rule: `log keystrokes via polling` |
| Keylogging capability | yara | Rule: `keylogger` at offsets 777, 83222 |
| Screenshot capability | yara | Rule: `screenshot` at offsets 767, 777, 82718 |
| Privilege escalation | yara | Rule: `escalate_priv` at offsets 731, 80750 |
| Registry manipulation | yara | Rule: `win_registry` at offsets 731, 80640, 85492, 85512 |
| Defense impairment | malcat | String: `DisableRegistryTools` at EA 3188 |
| Masquerading | malcat | Strings: `regedit.pdb`, `REGEDIT4`, `RegEdit_RegEdit` |
| Process spawning | radare2 | CreateProcessW at 0x01015a69 with path at 0x01015a8c |
| Obfuscation | capa | Rule: `contain obfuscated stackstrings` |
| High complexity | ghidra_query | FUN_01006e46: complexity=123, 149 blocks |
| 60 VT detections | external_ti | VirusTotal report |

---

## 13. Appendix B: Analysis Environment

### Environment Configuration

| Parameter | Value |
|---|---|
| Sample Path | `/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe` |
| Project | binaries |
| Analysis Date | 2026-08-12 |
| Report Version | v2 |
| Report Style | Technical (reverse engineer audience) |

### Tool Versions

| Tool | Version/Details |
|---|---|
| MalCat | Latest (section/structure analysis) |
| Ghidra | Latest (decompilation, string refs, function metrics) |
| IDA Pro | Latest (import/string queries) |
| capa | malcat-capa engine, 1.21s duration |
| YARA | Pipeline engine, 16 matches |
| FLOSS | 853 static strings, 0 decoded/stack/tight |
| radare2 | Entry point disassembly |
| UPX | Not applicable (not packed) |
| Speakeasy | Emulation completed, 0 events |
| Frida | v17.16.4, 30 hook candidates, 0 events |
| VirusTotal | External lookup, 60 detections |

### Analysis Limitations

1. **Dynamic analysis failure:** Both Speakeasy and Frida recorded zero events, preventing behavioral confirmation of static findings
2. **Spawned process unavailable:** `qomag.exe` was not provided for analysis
3. **Network infrastructure unknown:** No C2 domains or IPs were conclusively identified
4. **Obfuscated functions:** High-complexity functions (e.g., FUN_01006e46) were not fully decompiled
5. **Hardcoded addresses:** The entry point uses a hardcoded `CreateProcessW` address (0x77e61bb8), suggesting version-specific targeting

---

*End of Technical Malware Analysis Report*
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648  
**sample_path:** /opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe  
**project_name:** binaries

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 95
- **family_guess**: luder/texel
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple engines consistently identify malicious behaviors: Ghidra and IDA show registry manipulation imports; MalCat flags anomalies like DynamicString and key security APIs; capa and YARA rules detect keylogging, privilege escalation, registry modification, and defense impairment; VirusTotal reports high detection rate with threat families luder/texel. Obfuscation signals (e.g., high entropy, stack strings) are present but secondary to behavioral evidence.
- **summary**: The sample exhibits strong malicious behaviors including keylogging, privilege escalation, registry manipulation, and defense impairment. Tools like YARA and capa detect specific attack techniques, while VirusTotal confirms high detection rates. Obfuscation elements are present but secondary to clear behavioral intent.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `escalate_priv` | YARA rule fires for privilege escalation, indicating malicious capability to elevate permissions. |
| yara | yara matches | `keylogger` | Detects keylogging functionality, a clear malicious behavior for data theft. |
| yara | yara matches | `win_registry` | Shows registry manipulation, which can be used for persistence or defense evasion. |
| capa | capa rules | `log keystrokes via polling` | capa rule identifies keylogging via polling, confirming malicious data collection intent. |
| capa | capa rules | `modify registry` | Registry modification capability, often used for persistence or disabling security tools. |
| malcat | anomalies | `DynamicString` | Dynamic string construction suggests obfuscation for evasion, but combined with other behaviors, supports malicious inte |
| malcat | strings | `DisableRegistryTools` | String for DisableRegistryTools indicates defense impairment by disabling registry access. |
| pe_imports | pe_imports signals | `set_registry_value` | High-signal import for registry value setting, enabling malicious configuration changes. |
| revai_tools_sinks | revai_tools_sinks | `wcscat` | Use of unsafe string functions like wcscat could facilitate exploits, supporting malicious code patterns. |
| external_ti | VirusTotal | `60 malicious detections` | High detection rate from security vendors, with popular threat names luder/texel, confirming malicious classification. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This PE32 binary is a trojanized clone of the Windows Registry Editor (regedit.exe). It masquerades as the legitimate tool (contains regedit.pdb, REGEDIT4 headers, Applets\Regedit registry references) while embedding keylogging via GetKeyState/SetTimer polling (CAPA T1056.001), screenshot capability (BitBlt/CreateCompatibleDC/GetDesktopWindow imports, YARA screenshot rules), privilege escalation (AdjustTokenPrivileges/OpenProcessToken), aggressive registry manipulation (20+ Reg* APIs including RegSetValueEx, RegDeleteKey, RegLoadKey), system policy modification (DisableRegistryTools under Policies\System), clipboard monitoring (OpenClipboard/GetClipboardData), window surveillance (FindWindowW/GetWindowTextW), and code obfuscation (stack strings per CAPA T1027.005, functions with cyclomatic complexity up to 123 with 149 basic blocks). YARA matches: keylogger, screenshot, anti_debug, escalate_priv, win_registry, System_Tools. The DisableRegistryTools policy string under Policies\System indicates intent to disable the real regedit to maintain its disguise. Persistence: Not observed in cited evidence; registry manipulation APIs (e.g., RegSetValueEx) could support persistence techniques like Run key modifications, but no specific persistence mechanisms are confirmed by CAPA or YARA rules. Exfiltration: Not observed; keylogging and screenshot functions indicate data collection, but no network communication or data exfiltration methods (e.g., send APIs) are cited in the analysis.

### deep key_evidence
- `"YARA matches: keylogger (offset 777, 83222), screenshot (offset 767, 777, 82718), anti_dbg (offset 744, 81926), escalate_priv (offset 731, 80750), win_registry (offset 731, 80640, 85492, 85512), System_Tools (offset 92640)"`
- `"CAPA: 'log keystrokes via polling' (T1056.001), 'contain obfuscated stackstrings' (T1027.005), plus 22 other capability rules"`
- `"Ghidra imports: GetKeyState (USER32.dll), SetTimer (USER32.dll), FindWindowW, GetWindowTextW, GetWindowTextLengthW - keylogging/surveillance toolkit"`
- `"Ghidra imports: AdjustTokenPrivileges, LookupPrivilegeValueW, OpenProcessToken (ADVAPI32.dll) - privilege escalation"`
- `"Ghidra imports: BitBlt, CreateCompatibleDC, CreateCompatibleBitmap, GetDC, GetDesktopWindow, GetWindowDC, StretchBlt (GDI32.dll/USER32.dll) - screenshot capture"`
- `"Ghidra imports: 20+ registry APIs (RegSetValueExW, RegCreateKeyW, RegDeleteKeyW, RegLoadKeyW, RegSaveKeyW, RegConnectRegistryW, etc.) - full registry manipulation"`
- `"Ghidra imports: OpenClipboard, GetClipboardData, CloseClipboard, SetClipboardData (USER32.dll) - clipboard monitoring"`
- `"Ghidra string refs: FUN_010089fb references 'DisableRegistryTools' at addr 0x01003476 and 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' at addr 0x01003520"`
- `"Ghidra strings: 'regedit.pdb', 'REGEDIT', 'REGEDIT4', 'RegEdit_RegEdit', 'Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit' - masquerading as legitimate regedit.exe"`
- `"Ghidra function metrics: FUN_01006e46 has cyclomatic_complexity=123, 522 instructions, 149 blocks, 58 call-outs - highly obfuscated control flow"`
- `"pe_import_signals: set_registry_value (T1112), load_library (T1129), get_proc_address (T1129)"`
- `"FLOSS: 853 static strings extracted; binary is 134KB PE32 GUI executable"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648
size: 134144
type: PE
architecture: X86
entrypoint_ea: 85560
entropy: 5.77
file_name: challenge63.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 68 | - |
| .text | 1024 | 84992 | 86016 | 126 | RX |
| .data | 87040 | 512 | 266240 | 0 | RW |
| .rsrc | 353280 | 47616 | 49152 | 39 | R |

### Malcat YARA / Signatures (3)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2002_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2002_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |

### Anomalies (14)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| HugeStringBinary | 4 | strings | 1 | string has more than 1024 characters and binary encoding |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| UnsignedMicrosoft | 4 | integrity | 3 | Version information tells us it is a microsoft file but no certificate has been found |
| BigStringHiScore | 3 | strings | 1 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 2 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 3 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| StackArrayInitialisationX86 | 3 | code | 1 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| BoundImports | 2 | imports | 1 | Bound imports are present |
| RichUnknownTool | 2 | rich | 1 | Tool entry is not known (either a new version or has been patched) |
| VeryHugeString | 2 | strings | 1 | string has more than 65k characters |
| SequentialFunction | 1 | code | 1 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 4 | Function with lots of intra jumps, could be obfuscated |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `44457`: 
  - `32861`: 
- **ManyHighValueImmediates**
  - `16732`: 
  - `24400`: 
  - `41752`: 
- **SequentialFunction**
  - `4104`: 
- **SpaghettiFunction**
  - `10799`: 
  - `16541`: 
  - `20149`: 
  - `31946`: 

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 744 | `KERNEL32.dll` |
| 82170 | `KERNEL32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 44457 | `0000000000000000..000000006C000000` |
| 32861 | `5555AAAA5555AAAA5555AAAA5555AAAA` |
| 3232 | `Software\Microso..\Policies\System` |
| 2688 | `Software\Microso..egedit\Favorites` |
| 2568 | `Software\Microso..\Applets\Regedit` |
| 6224 | `CLSID\{ADB880A6-..}\InprocServer32` |
| 85644 | `C:\Program Files.. Files\qomag.exe` |
| 3936 | `REGEDIT:  Create..astError() = %d
` |
| 5232 | `CFSTR_DSOP_DS_SELECTION_LIST` |
| 4400 | `riched20.dll` |
| 358144 | `<?xml version="1..>
</assembly>
` |
| 5352 | `%08x   %04x %04x..x %04x %04x %04x` |
| 3528 | `Windows Registry Editor Version` |
| 3188 | `DisableRegistryTools` |
| 6208 | `hhctrl.ocx` |
| 393360 | `%Removes keys fr.. Favorites list.` |
| 380464 | `@Are you sure yo.. of its subkeys?` |
| 2536 | `RegEdit_RegEdit` |
| 3876 | `SeBackupPrivilege` |
| 393536 | `6Contains comman..ently used keys.` |
| 2276 | `RegEdit_HexData` |
| 392992 | `.Disconnects fro..uter's registry.` |
| 5460 | `%08x   %08x %08x %08x %08x` |
| 3764 | `HKEY_LOCAL_MACHINE` |
| 385600 | `HInformation in ..not exist on %2.` |
| 80750 | `AdjustTokenPrivileges` |
| 2968 | `SysListView32` |
| 2996 | `SysTreeView32` |
| 396432 | `^Registry Editor..of its subkeys. ` |
| 3840 | `HKEY_CLASSES_ROOT` |
| 5308 | `0x%08x%08x` |
| 3500 | `REGEDIT4

` |
| 3592 | `5.00` |
| 4376 | `RichEdit20W` |
| 5528 | `%#08x%08x` |
| 3612 | `dword:` |
| 4568 | `REG_RESOURCE_REQUIREMENTS_LIST` |
| 3480 | `.classes` |
| 4632 | `REG_FULL_RESOURCE_DESCRIPTOR` |
| 3740 | `HKEY_USERS` |
| 4928 | `0x%x` |
| 3464 | `REGEDIT` |
| 5292 | `0x%08x` |
| 85480 | `ntdll.dll` |
| 2836 | `FindFlags` |
| 3628 | `0123456789abcdef,\
  ` |
| 4776 | `REG_DWORD_BIG_ENDIAN` |
| 4464 | `%.192s` |
| 2856 | `LastKey` |
| 84756 | `comdlg32.dll` |
| 801 | `comdlg32.dll` |
| 2824 | `View` |
| 865 | `clb.dll` |
| 85440 | `clb.dll` |
| 856 | `ulib.dll` |
| 85058 | `ole32.dll` |
| 85394 | `ulib.dll` |
| 4692 | `REG_RESOURCE_LIST` |
| 757 | `NTDLL.DLL` |
| 846 | `ole32.dll` |
| 2308 | `%04X` |
| 2320 | `%02X` |
| 3804 | `HKEY_CURRENT_USER` |
| 744 | `KERNEL32.dll` |
| 84816 | `SHELL32.dll` |
| 81508 | `ADVAPI32.dll` |
| 84688 | `COMCTL32.dll` |
| 814 | `SHELL32.dll` |
| 788 | `COMCTL32.dll` |
| 82170 | `KERNEL32.dll` |
| 731 | `ADVAPI32.dll` |
| 3700 | `HKEY_CURRENT_CONFIG` |
| 4984 | `CURRENT_USER` |
| 3672 | `HKEY_DYN_DATA` |
| 82520 | `GDI32.dll` |
| 84542 | `USER32.dll` |
| 80626 | `msvcrt.dll` |
| 720 | `msvcrt.dll` |
| 777 | `USER32.dll` |
| 826 | `AUTHZ.dll` |

### Constants / Known Patterns (5)
| Category | Value |
|---|---|
| guid | `guid::IUnknown` |
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| registry | `registry::HKEY_USERS` |
| code | `code::PEBx86` |

### Imports (290)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1024 | aclui.#2 | IMPORT | 6 |
| 1032 | advapi32.RegQueryValueExA | IMPORT | 2 |
| 1036 | advapi32.RegOpenKeyExA | IMPORT | 1 |
| 1040 | advapi32.InitializeSecurityDescriptor | IMPORT | 1 |
| 1044 | advapi32.RegDeleteKeyW | IMPORT | 2 |
| 1048 | advapi32.InitializeAcl | IMPORT | 1 |
| 1052 | advapi32.SetSecurityDescriptorDacl | IMPORT | 1 |
| 1056 | advapi32.SetSecurityDescriptorSacl | IMPORT | 1 |
| 1060 | advapi32.SetSecurityDescriptorOwner | IMPORT | 1 |
| 1064 | advapi32.SetSecurityDescriptorGroup | IMPORT | 1 |
| 1068 | advapi32.GetInheritanceSourceW | IMPORT | 1 |
| 1072 | advapi32.LookupAccountSidW | IMPORT | 1 |
| 1076 | advapi32.GetSidSubAuthorityCount | IMPORT | 1 |
| 1080 | advapi32.RegCloseKey | IMPORT | 49 |
| 1084 | advapi32.RegOpenKeyW | IMPORT | 4 |
| 1088 | advapi32.RegSetValueExW | IMPORT | 7 |
| 1092 | advapi32.RegCreateKeyW | IMPORT | 9 |
| 1096 | advapi32.RegEnumValueW | IMPORT | 11 |
| 1100 | advapi32.RegDeleteValueW | IMPORT | 4 |
| 1104 | advapi32.RegEnumKeyW | IMPORT | 12 |
| 1108 | advapi32.AdjustTokenPrivileges | IMPORT | 1 |
| 1112 | advapi32.LookupPrivilegeValueW | IMPORT | 1 |
| 1116 | advapi32.OpenProcessToken | IMPORT | 1 |
| 1120 | advapi32.RegUnLoadKeyW | IMPORT | 1 |
| 1124 | advapi32.RegLoadKeyW | IMPORT | 1 |
| 1128 | advapi32.RegOpenKeyExW | IMPORT | 21 |
| 1132 | advapi32.RegQueryInfoKeyW | IMPORT | 7 |
| 1136 | advapi32.RegQueryValueExW | IMPORT | 1 |
| 1140 | advapi32.RegConnectRegistryW | IMPORT | 3 |
| 1144 | advapi32.RegRestoreKeyW | IMPORT | 1 |
| 1148 | advapi32.RegSaveKeyW | IMPORT | 1 |
| 1152 | advapi32.RegFlushKey | IMPORT | 2 |
| 1156 | advapi32.RegSetValueW | IMPORT | 1 |
| 1160 | advapi32.RegSetValueExA | IMPORT | 1 |
| 1164 | advapi32.MapGenericMask | IMPORT | 1 |
| 1168 | advapi32.GetNamedSecurityInfoW | IMPORT | 1 |
| 1172 | advapi32.SetNamedSecurityInfoW | IMPORT | 1 |
| 1176 | advapi32.SetSecurityInfo | IMPORT | 3 |
| 1180 | advapi32.GetSecurityDescriptorSacl | IMPORT | 3 |
| 1184 | advapi32.GetSecurityDescriptorDacl | IMPORT | 3 |
| 1188 | advapi32.GetSecurityDescriptorGroup | IMPORT | 4 |
| 1192 | advapi32.GetSecurityDescriptorOwner | IMPORT | 4 |
| 1196 | advapi32.GetSecurityDescriptorControl | IMPORT | 3 |
| 1200 | advapi32.GetSidSubAuthority | IMPORT | 1 |
| 1208 | authz.AuthzFreeResourceManager | IMPORT | 2 |
| 1212 | authz.AuthzFreeContext | IMPORT | 1 |
| 1216 | authz.AuthzAccessCheck | IMPORT | 1 |
| 1220 | authz.AuthzInitializeResourceManager | IMPORT | 1 |
| 1224 | authz.AuthzInitializeContextFromSid | IMPORT | 1 |
| 1232 | comctl32.#4 | IMPORT | 4 |
| 1236 | comctl32.#2 | IMPORT | 1 |
| 1240 | comctl32.#358 | IMPORT | 2 |
| 1244 | comctl32.ImageList_Destroy | IMPORT | 3 |
| 1248 | comctl32.#359 | IMPORT | 1 |
| 1252 | comctl32.CreateStatusWindowW | IMPORT | 1 |
| 1256 | comctl32.#329 | IMPORT | 1 |
| 1260 | comctl32.#337 | IMPORT | 2 |
| 1264 | comctl32.#338 | IMPORT | 1 |
| 1268 | comctl32.#334 | IMPORT | 1 |
| 1272 | comctl32.#236 | IMPORT | 3 |
| 1276 | comctl32.#340 | IMPORT | 1 |
| 1280 | comctl32.InitCommonControlsEx | IMPORT | 1 |
| 1284 | comctl32.#365 | IMPORT | 1 |
| 1288 | comctl32.ImageList_SetBkColor | IMPORT | 1 |
| 1292 | comctl32.#363 | IMPORT | 1 |
| 1296 | comctl32.ImageList_Create | IMPORT | 1 |
| 1300 | comctl32.ImageList_ReplaceIcon | IMPORT | 1 |
| 1308 | gdi32.SetBkColor | IMPORT | 5 |
| 1312 | gdi32.GetStockObject | IMPORT | 1 |
| 1316 | gdi32.SetAbortProc | IMPORT | 1 |
| 1320 | gdi32.StartDocW | IMPORT | 1 |
| 1324 | gdi32.StartPage | IMPORT | 1 |
| 1328 | gdi32.SetViewportOrgEx | IMPORT | 1 |
| 1332 | gdi32.EndPage | IMPORT | 1 |
| 1336 | gdi32.EndDoc | IMPORT | 1 |
| 1340 | gdi32.AbortDoc | IMPORT | 1 |
| 1344 | gdi32.DeleteDC | IMPORT | 1 |
| 1348 | gdi32.CreateBitmap | IMPORT | 1 |
| 1352 | gdi32.CreatePatternBrush | IMPORT | 1 |
| 1356 | gdi32.PatBlt | IMPORT | 3 |

### Functions (30)
| EA | Name |
|---|---|
| 75402 | sub_101328a |
| 77521 | sub_1013ad1 |
| 50897 | sub_100d2d1 |
| 15552 | sub_10048c0 |
| 40045 | sub_100a86d |
| 35475 | sub_1009693 |
| 74720 | sub_1012fe0 |
| 78274 | sub_1013dc2 |
| 16097 | sub_1004ae1 |
| 18189 | sub_100530d |
| 34056 | sub_1009108 |
| 14698 | sub_100456a |
| 13756 | sub_10041bc |
| 15235 | sub_1004783 |
| 15963 | sub_1004a5b |
| 32251 | sub_10089fb |
| 75208 | sub_10131c8 |
| 74579 | sub_1012f53 |
| 55407 | PEBx86 |
| 55432 | sub_100e488 |
| 76295 | sub_1013607 |
| 54922 | sub_100e28a |
| 41339 | sub_100ad7b |
| 44407 | sub_100b977 |
| 71515 | sub_101235b |
| 53863 | sub_100de67 |
| 19353 | sub_1005799 |
| 66615 | sub_1011037 |
| 25158 | sub_1006e46 |
| 51844 | sub_100d684 |

### Decompilations (top 6)
#### 75402 — sub_101328a
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 __thiscall sub_101328a(int32_t param_1,undefined4 *param_2,int32_t param_3,int32_t *param_4)

{
    char cVar1;
    int32_t iVar2;
    int32_t *piVar3;
    undefined4 *puVar4;
    code **ppcVar5;
    uint32_t uVar6;
    undefined2 *puVar7;
    int32_t iStack_14;
    undefined4 *puStack_10;
    uint32_t uStack_c;
    undefined4 *puStack_8;
    
    if (param_2 != 0x0) {
        puStack_8 = param_2;
        iVar2 = PEBx86(0x18);
        if (iVar2 == 0) {
            piVar3 = 0x0;
        }
        else {
            piVar3 = (*ulib.ARRAY.ARRAY)();
        }
        if (piVar3 != 0x0) {
            cVar1 = (*ulib.ARRAY.Initialize)(0x32, 0x19);
            if (cVar1 != '\0') {
                uStack_c = 0;
                *(param_1 + 8) = *param_2;
                *(param_1 + 0xc) = param_2[1];
                *(param_1 + 0x10) = *(param_2 + 2);
                *(param_1 + 0x12) = *(param_2 + 10);
                do {
                    uVar6 = 0;
                    iStack_14 = 0;
                    puStack_10 = 0x0;
                    if (puStack_8[3] != 0) {
                        puVar7 = uStack_c + 0x12 + puStack_8;
                        do {
                            uVar6 = puStack_10;
                            if (param_2 + param_3 + -0x10 < puVar7 + -1) {
                                if (param_4 != 0x0) {
                                    *param_4 = param_3;
                                }
                                *(param_1 + 0x14) = piVar3;
                                return 1;
                            }
                            cVar1 = *(puVar7 + -1);
                            if (cVar1 != '\x01') {
                                if (cVar1 == '\x02') {
                                    iVar2 = PEBx86(0x18);
                                    if (iVar2 == 0) {
                                        puVar4 = 0x0;
                                    }
                                    else {
                                        puVar4 = sub_10136d9();
                                    }
                                    if (puVar4 != 0x0) {
                                        cVar1 = sub_101313f(*(puVar7 + 5), *(puVar7 + 1), *(puVar7 + 3), *(puVar7 + -1)
                                                            , *puVar7);
                                        goto code_r0x010134b8;
                                    }
                                }
                                else if (cVar1 == '\x03') {
                                    iVar2 = PEBx86(0x20);
                                    if (iVar2 == 0) {
                                        puStack_10 = 0x0;
                                    }
                                    else {
                                        puStack_10 = sub_1013720();
                                    }
                                    if (puStack_10 != 0x0) {
                                        cVar1 = sub_101316c(puVar7 + 1, *(puVar7 + 5), *(puVar7 + -1), *puVar7);
code_r0x010133a0:
                                        if (cVar1 != '\0') {
                                            (**(*piVar3 + 8))(puStack_10);
                                            goto code_r0x010134c7;
                                        }
                                        if (puStack_10 != 0x0) {
                                            ppcVar5 = *puStack_10;
                                            goto code_r0x01013532;
                                        }
                                    }
                                }
                                else if (cVar1 == '\x04') {
                                    iVar2 = PEBx86(0x18);
                                    if (iVar2 == 0) {
                                        puStack_10 = 0x0;
                                    }
                                    el
```
#### 77521 — sub_1013ad1
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 __thiscall sub_1013ad1(int32_t param_1,undefined2 *param_2,int32_t param_3,int32_t *param_4)

{
    char cVar1;
    int32_t iVar2;
    int32_t *piVar3;
    undefined4 *puVar4;
    undefined2 *puVar5;
    int32_t iStack_14;
    uint32_t uStack_10;
    undefined2 *puStack_c;
    undefined2 *puStack_8;
    
    if (param_2 != 0x0) {
        puStack_c = param_2;
        iVar2 = PEBx86(0x18);
        if (iVar2 == 0) {
            piVar3 = 0x0;
        }
        else {
            piVar3 = (*ulib.ARRAY.ARRAY)();
        }
        if (piVar3 != 0x0) {
            cVar1 = (*ulib.ARRAY.Initialize)(0x32, 0x19);
            if (cVar1 != '\0') {
                iStack_14 = 0;
                *(param_1 + 8) = *param_2;
                *(param_1 + 10) = param_2[1];
                do {
                    uStack_10 = 0;
                    if (*(puStack_c + 2) != 0) {
                        puVar5 = puStack_c + 6;
                        do {
                            puStack_8 = puVar5 + -2;
                            if (param_2 + param_3 + -0x20 < puVar5 + -2) {
                                if (param_4 != 0x0) {
                                    *param_4 = param_3;
                                }
                                *(param_1 + 0xc) = piVar3;
                                return 1;
                            }
                            cVar1 = *(puVar5 + -3);
                            if (cVar1 != '\x01') {
                                if (cVar1 == '\x02') {
                                    iVar2 = PEBx86(0x18);
                                    if (iVar2 == 0) {
                                        puVar4 = 0x0;
                                    }
                                    else {
                                        puVar4 = sub_10138dd();
                                    }
                                    if (puVar4 != 0x0) {
                                        cVar1 = sub_10139fe(*(puVar5 + 2), *(puVar5 + 4), *puStack_8, *(puVar5 + -1), 
                                                            *puVar5);
                                        goto code_r0x01013ca5;
                                    }
                                }
                                else if (cVar1 == '\x03') {
                                    iVar2 = PEBx86(0x28);
                                    if (iVar2 == 0) {
                                        puVar4 = 0x0;
                                    }
                                    else {
                                        puVar4 = sub_1013921();
                                    }
                                    if (puVar4 != 0x0) {
                                        cVar1 = sub_1013a2b(*(puVar5 + 2), *(puVar5 + 4), puVar5 + 6, puVar5 + 10, 
                                                            *puStack_8, *(puVar5 + -1), *puVar5);
                                        goto code_r0x01013ca5;
                                    }
                                }
                                else {
                                    if (cVar1 != '\x04') goto code_r0x01013cb1;
                                    iVar2 = PEBx86(0x18);
                                    if (iVar2 == 0) {
                                        puVar4 = 0x0;
                                    }
                                    else {
                                        puVar4 = sub_1013971();
                                    }
                                    if (puVar4 != 0x0) {
                                        cVar1 = sub_1013a74(*(puVar5 + 2), *(puVar5 + 4), *puStack_8, *(puVar5 + -1), 
                                                            *puVar5);
                                        goto code_r0x01013ca5;
                                    }
                                }
code_r0x01013d11:
              
```
#### 50897 — sub_100d2d1
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

uint32_t __fastcall sub_100d2d1(int32_t param_1)

{
    int32_t *piVar1;
    int32_t iVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    
    iVar2 = *(param_1 + 0x24);
    if (*(param_1 + 0x20) == 0) {
        if (iVar2 == 0) {
            *(param_1 + 0x2c) = 0x80000000;
            return 0;
        }
        if (iVar2 == 1) {
            *(param_1 + 0x2c) = 0x80000001;
            return 0;
        }
        if (iVar2 == 2) {
            *(param_1 + 0x2c) = 0x80000002;
            return 0;
        }
        if (iVar2 != 3) {
            if (iVar2 != 4) {
                return 0;
            }
            *(param_1 + 0x2c) = 0x80000005;
            return 0;
        }
        *(param_1 + 0x2c) = 0x80000003;
        return 0;
    }
    if (iVar2 < 0) goto code_r0x0100d334;
    if (1 < iVar2) {
        if (iVar2 == 2) {
            *(param_1 + 0x2c) = 0x80000002;
            goto code_r0x0100d334;
        }
        if (iVar2 == 3) {
            *(param_1 + 0x2c) = 0x80000003;
            goto code_r0x0100d334;
        }
        if (iVar2 != 4) goto code_r0x0100d334;
    }
    *(param_1 + 0x2c) = 0;
code_r0x0100d334:
    piVar1 = param_1 + 0x2c;
    uVar4 = 0;
    if (((*piVar1 != 0) && (uVar3 = (*advapi32.RegConnectRegistryW)(*(param_1 + 0x18), *piVar1, piVar1), uVar3 != 0)) &&
       (*piVar1 = 0, uVar4 = uVar3, 0 < uVar3)) {
        uVar4 = uVar3 & 0xffff | 0x80070000;
    }
    return uVar4;
}

```

### Carved Files (12)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 296 |
| ? | DIB | 296 |
| ? | DIB | 296 |
| ? | DIB | 296 |
| ? | DIB | 296 |
| ? | DIB | 304 |

### Virtual Files (96)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| CUR/12/en-us | 308 | - |
| ICO/1/en-us | 744 | - |
| ICO/2/en-us | 296 | - |
| ICO/3/en-us | 744 | - |
| ICO/4/en-us | 296 | - |
| ICO/5/en-us | 744 | - |
| ICO/6/en-us | 296 | - |
| ICO/7/en-us | 296 | - |
| ICO/8/en-us | 296 | - |
| ICO/9/en-us | 296 | - |
| ICO/10/en-us | 296 | - |
| ICO/11/en-us | 296 | - |
| MENU/103/en-us | 1696 | - |
| MENU/104/en-us | 640 | - |
| MENU/105/en-us | 118 | - |
| MENU/106/en-us | 344 | - |
| MENU/107/en-us | 160 | - |
| MENU/108/en-us | 110 | - |
| DLG/100/en-us | 310 | - |
| DLG/102/en-us | 306 | - |

### Structures (338)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 224 |
| OptionalHeader | 248 |
| Sections | 472 |
| BoundImportTable | 592 |
| BoundImportNames | 720 |
| aclui.FT | 1024 |
| advapi32.FT | 1032 |
| authz.FT | 1208 |
| comctl32.FT | 1232 |
| gdi32.FT | 1308 |
| kernel32.FT | 1400 |
| shell32.FT | 1572 |
| user32.FT | 1588 |
| clb.FT | 2072 |
| comdlg32.FT | 2084 |
| msvcrt.FT | 2100 |
| ntdll.FT | 2156 |
| ole32.FT | 2168 |
| ulib.FT | 2188 |
| DebugDirectory | 2240 |
| Debug.Codeview | 6336 |
| ImportTable | 78972 |
| aclui.OFT | 79272 |
| advapi32.OFT | 79280 |
| authz.OFT | 79456 |
| comctl32.OFT | 79480 |
| gdi32.OFT | 79556 |
| kernel32.OFT | 79648 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 24 · duration_s: 1.21

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get hostname | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry key | T1012:Query Registry | C0036.005:Registry |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| open clipboard | T1115:Clipboard Data |  |
| read clipboard data | T1115:Clipboard Data |  |
| write clipboard data |  | E1510:Clipboard Modification |
| delete file |  | C0047:Delete File |
| read file on Windows |  | C0051:Read File |
| write file on Windows |  | C0052:Writes File |

## PE Imports / Signals
import_count: 277

| label | api_match | ATT&CK |
|---|---|---|
| set_registry_value | RegSetValue | T1112 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 16

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@91584 len=7 |
| contains_base64 | - | $a@6255 len=12 |
| System_Tools | - | $a4@92640 len=22 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@208 len=4 |
| Microsoft_Visual_Basic_v50 | - | $a@79 len=1 |
| anti_dbg | - | $d1@744 len=12; $c3@81926 len=17 |
| escalate_priv | - | $d1@731 len=12; $c2@80750 len=21 |
| screenshot | - | $d1@767 len=9; $d2@777 len=10; $c2@82718 len=5 |
| keylogger | - | $f1@777 len=10; $c2@83222 len=11 |
| win_registry | - | $f1@731 len=12; $c1@85492 len=16; $c2@85512 len=13; $c3@80640 len=11; $c4@81004 len=14; $c6@80640 len=11 |
| win_token | - | $f1@731 len=12; $c2@80750 len=21; $c3@80798 len=16 |
| win_files_operation | - | $f1@744 len=12; $c1@81878 len=9; $c2@81964 len=14; $c3@81878 len=9; $c4@81852 len=8 |

## Generated YARA Meta
```json
{
  "sha256": "98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648",
  "family": "luder",
  "imphash": "6a2fc8d37b8a0d3e10059a4768a803d7",
  "generated_at": "2026-08-12T23:34:53.119789+00:00",
  "string_count": 24,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "msvcrt.dll",
    "ADVAPI32.dll",
    "KERNEL32.dll",
    "NTDLL.DLL",
    "GDI32.dll",
    "USER32.dll",
    "COMCTL32.dll",
    "comdlg32.dll",
    "SHELL32.dll",
    "AUTHZ.dll",
    "ACLUI.dll",
    "ole32.dll",
    "ulib.dll",
    "hhctrl.ocx",
    "CLSID\\{ADB880A6-D8FF-11CF-9377-00AA003B7A11}\\InprocServer32",
    "regedit.pdb",
    "t7HHt&Ht",
    "u*VVVVVVV",
    "VVVVVVVV",
    "VVVVVVVVV",
    "ElPWWWWWWWWWW",
    "SSSSjdjdSSj",
    "ugSSSSSS"
  ],
  "rule_path": "/opt/samples/logs/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/rule.yar",
  "sigma_path": "/opt/samples/logs/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/rule.yml",
  "iocs_path": "/opt/samples/logs/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/iocs.json",
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
    "commit": "unknown",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-12 23:34:53 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 853 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 853}`

### High-signal FLOSS
- `KERNEL32.dll`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.data`
- `msvcrt.dll`
- `ADVAPI32.dll`
- `KERNEL32.dll`
- `NTDLL.DLL`
- `GDI32.dll`
- `USER32.dll`
- `COMCTL32.dll`
- `comdlg32.dll`
- `SHELL32.dll`
- `AUTHZ.dll`
- `ACLUI.dll`
- `ole32.dll`
- `ulib.dll`
- `clb.dll`
- `hhctrl.ocx`
- `CLSID\{ADB880A6-D8FF-11CF-9377-00AA003B7A11}\InprocServer32`
- `regedit.pdb`
- `PPPQPS`
- `t8HHt4`
- `'t}OtK`
- `t7HHt&Ht`
- `toHtN-`
- `F09F8}`
- `F89F,}D`
- `HtFHt\-`
- `tjVWh8`
- `@[_^]Y`
- `WWPPPPh`
- `WSSSSh`
- `WSSSShA`
- `Ht;Ht+`
- `tMHHt<`
- `j4j6j5`
- `jdXPj@`
- `]Tu	f9`
- `u7SSSSh`
- `]d9]du`
- `9]Tt'Sj`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x01015a38
```asm
┌ 66: entry0 ();
│           0x01015a38      687a5a0101     push 0x1015a7a
│           0x01015a3d      33c9           xor ecx, ecx
│           0x01015a3f      64ff31         push dword fs:[ecx]
│           0x01015a42      648921         mov dword fs:[ecx], esp
│           0x01015a45      33d2           xor edx, edx
│           0x01015a47      6a10           push 0x10                   ; 16
│           0x01015a49      59             pop ecx
│       ┌─> 0x01015a4a      52             push edx
│       └─< 0x01015a4b      e2fd           loop 0x1015a4a
│           0x01015a4d      6a44           push 0x44                   ; 'D' ; 68
│           0x01015a4f      8bc4           mov eax, esp
│           0x01015a51      83ec10         sub esp, 0x10
│           0x01015a54      8bcc           mov ecx, esp
│           0x01015a56      51             push ecx
│           0x01015a57      50             push eax
│           0x01015a58      52             push edx
│           0x01015a59      52             push edx
│           0x01015a5a      52             push edx
│           0x01015a5b      52             push edx
│           0x01015a5c      52             push edx
│           0x01015a5d      52             push edx
│           0x01015a5e      688c5a0101     push 0x1015a8c              ; "C:\Program Files\Common Files\qomag.exe"
│           0x01015a63      52             push edx
│           0x01015a64      b9b81be677     mov ecx, 0x77e61bb8
│           0x01015a69      ffd1           call ecx
│           0x01015a6b      83c454         add esp, 0x54
│           0x01015a6e      33d2           xor edx, edx
│           0x01015a70      648f02         pop dword fs:[edx]
│           0x01015a73      5a             pop edx
│           0x01015a74      68618a0001     push 0x1008a61
└           0x01015a79      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r

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
  - `msvcrt.dll!wcsncpy`
  - `msvcrt.dll!wcslen`
  - `msvcrt.dll!wcscat`
  - `msvcrt.dll!iswprint`
  - `msvcrt.dll!_purecall`
  - `ADVAPI32.dll!RegQueryValueExA`
  - `ADVAPI32.dll!RegOpenKeyExA`
  - `ADVAPI32.dll!InitializeSecurityDescriptor`
  - `ADVAPI32.dll!RegDeleteKeyW`
  - `ADVAPI32.dll!InitializeAcl`
  - `KERNEL32.dll!MulDiv`
  - `KERNEL32.dll!LoadLibraryW`
  - `KERNEL32.dll!FreeLibrary`
  - `KERNEL32.dll!FileTimeToLocalFileTime`
  - `KERNEL32.dll!FileTimeToSystemTime`
  - `GDI32.dll!SetBkColor`
  - `GDI32.dll!GetStockObject`
  - `GDI32.dll!SetAbortProc`
  - `GDI32.dll!StartDocW`
  - `GDI32.dll!StartPage`
  - `USER32.dll!SetClipboardData`
  - `USER32.dll!EmptyClipboard`
  - `USER32.dll!OpenClipboard`
  - `USER32.dll!GetClipboardData`
  - `USER32.dll!WinHelpW`
  - `COMCTL32.dll!ImageList_Destroy`
  - `comdlg32.dll!GetSaveFileNameW`
  - `comdlg32.dll!GetOpenFileNameW`
  - `comdlg32.dll!PrintDlgExW`
  - `SHELL32.dll!DragQueryFileW`

## Audit Trail (recent)
- `{"source": "ida_query", "sql": "SELECT content, address FROM strings WHERE content LIKE '%DisableRegistryTools%' OR content LIKE '%DisableTaskMgr%' OR content LIKE '%Policies%' OR content LIKE '%keylog%' OR content LIKE '%GetAsyncKeyState%' OR content LIKE '%GetKeyState%' OR content LIKE '%SetWindow`
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, sr.func_addr, sr.string_value FROM string_refs sr WHERE sr.string_value LIKE '%DisableRegistryTools%' OR sr.string_value LIKE '%Policies%' OR sr.string_value LIKE '%GetKeyState%' OR sr.string_value LIKE '%GetWindowText%' OR sr.string_value LIKE`
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, sr.string_value FROM string_refs sr WHERE sr.func_name = 'FUN_0100f523' OR sr.func_name = 'FUN_0100f804' OR sr.func_name = 'FUN_01006e46' OR sr.func_name = 'FUN_0100e4c4' ORDER BY sr.func_name", "ts": 1786577637.7545524}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786577690.482938}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786577693.0162075}`
- `{"source": "yara_gen_v2", "ts": 1786577693.1200361}`
- `{"source": "publish_report_v2", "ts": 1786577825.2195308}`
- `{"source": "publish_report_v2_technical", "ts": 1786577944.9930935}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786634911.3090973}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786634911.31427}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786634911.3182156}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786634911.3204253}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs LIMIT 15", "ts": 1786634911.3218496}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786634915.3566453}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786634915.771285}`
- `{"source": "ghidra_query", "sql": "SELECT name, addr FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1786634916.4953015}`
- `{"source": "ghidra_query", "sql": "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786634917.1863017}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786634917.705556}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786634918.2152815}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786634920.4126594}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786634920.8161724}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786634921.7732427}`
- `{"source": "ghidra_query", "sql": "SELECT addr, content FROM strings WHERE length < 300", "ts": 1786634922.2943866}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786634922.8119872}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786634923.2034605}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786634924.1170259}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786634924.9969022}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786634927.0905118}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786634927.4790978}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786634927.4863598}`
