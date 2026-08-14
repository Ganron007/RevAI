> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 15:45:34 UTC

## 1. Executive Summary
This sample (SHA256: 98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648) is a malicious PE32 executable that masquerades as the legitimate Windows Registry Editor (regedit.exe). It exhibits multiple hostile behaviors including keylogging, privilege escalation, aggressive registry manipulation, screenshot capture, and defense impairment by disabling registry tools. Tools such as capa and YARA detect specific attack techniques, while VirusTotal reports high detection rates with threat families luder/texel. Obfuscation elements like stack strings and high cyclomatic complexity functions are present. We assess with high confidence that this is a trojanized clone designed for data theft and system compromise. (source: deep_dive_agentic, summary; source: llm_judge, verdict)

## 2. Sample Metadata
The binary is a 134KB PE32 GUI executable for x86 architecture, with an entropy of 5.77. Basic metadata includes: SHA256: 98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648, sample path: /opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe, project: binaries, entry point at EA 85560. (source: malcat, file_summary)

## 3. File Layout & Structural Analysis
The PE file has four sections as listed below, with the .text section containing executable code and high entropy of 126, indicating potential obfuscation or packing.

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 68 | - |
| .text | 1024 | 84992 | 86016 | 126 | RX |
| .data | 87040 | 512 | 266240 | 0 | RW |
| .rsrc | 353280 | 47616 | 49152 | 39 | R |

(source: malcat, File Layout)

Malcat identified 14 anomalies, including DynamicString at EAs 44457 and 32861, suggesting dynamic string construction for evasion, and SpaghettiFunction at multiple EAs (10799, 16541, 20149, 31946), indicating obfuscated control flow. Other anomalies like CrossSectionJump and InvalidChecksum may point to patching or malware injection. (source: malcat, anomalies)

Structural analysis reveals 338 structures, including standard PE headers and rich header information. The binary contains bound imports and a debug directory with regedit.pdb, masquerading as legitimate software. (source: malcat, structures)

## 4. Static Code Analysis
Static analysis reveals extensive malicious capabilities. The import table shows 277 imports, with high-signal ones such as set_registry_value (RegSetValue, T1112), load_library (LoadLibrary, T1129), and get_proc_address (GetProcAddress, T1129) for dynamic API resolution. (source: pe_imports, pe_imports signals)

capa identifies 24 capability rules, including keylogging via polling (T1056.001), registry modification (T1112), and obfuscated stack strings (T1027.005). Full capa rules table:

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005 | B0032.020, B0032.017 |
| log keystrokes via polling | T1056.001 | F0002.002 |
| ... (other rules omitted for brevity; see evidence pack) |

(source: capa, capa rules)

YARA matches include keylogger, screenshot, escalate_priv, win_registry, and anti_dbg rules. For example, keylogger matches at offsets 777 and 83222, and escalate_priv at 731 and 80750. (source: yara, yara matches)

High-signal strings include "DisableRegistryTools" at EA 3188 (source: malcat, strings) and "regedit.pdb" at EA 7976, indicating masquerading as regedit.exe. (source: deep_dive_agentic, key_evidence)

Ghidra imports confirm key capabilities: GetKeyState and SetTimer for keylogging, AdjustTokenPrivileges for privilege escalation, BitBlt and CreateCompatibleDC for screenshots, and over 20 registry APIs for manipulation. Function metrics show FUN_01006e46 with cyclomatic complexity 123, 149 blocks, indicating highly obfuscated code. (source: deep_dive_agentic, key_evidence)

Radare2 disassembly at entry point (0x01015a38) shows setup for process creation, pushing "C:\Program Files\Common Files\qomag.exe" as a target path. (source: radare2, disassembly)

FLOSS extracted 853 static strings, with no decoded or stack strings observed. (source: floss, FLOSS Strings)

## 5. Behavioral & Dynamic Analysis
Dynamic analysis results are limited: Speakeasy recorded no API calls or events, and Frida probe did not observe runtime behavior. We assess that static indicators are sufficient for behavioral conclusions. (source: speakeasy, speakeasy_ok; source: frida_probe, frida_available)

From static analysis, we infer behaviors: keylogging via polling (source: capa, capa rules, rule: log keystrokes via polling), registry manipulation for persistence or defense evasion (source: yara, yara matches, rule: win_registry), and clipboard monitoring via OpenClipboard/GetClipboardData imports (source: deep_dive_agentic, key_evidence). However, no network exfiltration was observed in static evidence. (source: deep_dive_agentic, summary)

## 6. Network Indicators & C2
Network indicators are sparse: YARA matched an IP address at offset 91584 (source: yara, yara matches, rule: IP) and a domain regex at offset 0 (source: yara, yara matches, rule: domain), but no active C2 communication or exfiltration APIs were identified in imports or behavior. We assess that exfiltration methods are not present in this sample or require dynamic execution not observed. (source: deep_dive_agentic, summary)

## 7. Capabilities Assessment
Based on evidence, the sample has capabilities for data collection (keylogging, screenshots, clipboard), system manipulation (registry changes, privilege escalation), and evasion (obfuscation, masquerading). Key capabilities from capa and imports include: log keystrokes via polling (T1056.001), modify registry (T1112), open clipboard (T1115), and contain obfuscated stack strings (T1027.005). (source: capa, capa rules; source: pe_imports, pe_imports signals)

## 8. Indicators of Compromise
IOCs include: file hash SHA256: 98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648, strings such as "DisableRegistryTools" (EA 3188) (source: malcat, strings), "regedit.pdb" (source: deep_dive_agentic, key_evidence), and registry paths like "Software\Microsoft\Windows\CurrentVersion\Policies\System" (source: deep_dive_agentic, key_evidence). Network indicators: IP at offset 91584 (source: yara, yara matches, rule: IP). (source: external_ti, VirusTotal)

## 9. Detection Engineering
Detection can leverage YARA rules for keylogging and privilege escalation (source: yara, yara matches), capa rules for capability detection (source: capa, capa rules), and behavioral signatures for registry manipulation. For example, monitor for unusual regedit.exe behavior or registry changes under Policies\System. High entropy in .text section may indicate obfuscation. (source: malcat, File Layout)

## 10. MITRE ATT&CK Mapping
The sample maps to multiple ATT&CK techniques based on capa rules and imports: T1056.001 (Keylogging), T1112 (Modify Registry), T1027.005 (Obfuscated Files or Information), T1115 (Clipboard Data), and T1012 (Query Registry). Full mapping from capa:

| Rule | ATT&CK |
|---|---|
| log keystrokes via polling | T1056.001 |
| modify registry | T1112 |
| contain obfuscated stackstrings | T1027.005 |
| ... (other techniques from evidence) |

(source: capa, capa rules; source: pe_imports, pe_imports signals)

## 11. What We Don't Know
Gaps in analysis include: specific persistence mechanisms (registry Run keys are possible but not confirmed), exfiltration methods or C2 protocols, and full runtime behavior due to lack of dynamic observation. We do not know if the sample has worm-like propagation or additional payloads. Confidence in behavioral inferences is moderate based on static evidence alone. (source: deep_dive_agentic, summary)

## 12. Appendix A: Tool Evidence Trail
Tools used and key findings: Malcat provided file layout, anomalies, strings, and imports (source: malcat). capa identified 24 capability rules (source: capa). YARA matched 16 rules including keylogger and escalate_priv (source: yara). FLOSS extracted 853 static strings (source: floss). radare2 disassembled entry point (source: radare2). UPX unpacking failed (upx_ok: False) (source: upx_unpack). Speakeasy and Frida showed no runtime activity (source: speakeasy; source: frida_probe). VirusTotal reported 60 malicious detections (source: external_ti).

## 13. Appendix B: Analysis Environment
Analysis was based on provided structured evidence from tools including Malcat, capa, YARA, FLOSS, radare2, Ghidra, and IDA. The environment details are inferred from tool outputs, with the sample analyzed as a PE32 binary in a static context. No dynamic sandbox results were recorded.
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
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
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
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 91584,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 6255,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": [
        {
          "id": "$a4",
          "offset": 92640,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 208,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 79,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 744,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 81926,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "escalate_priv",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 731,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 80750,
          "length": 21,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "screenshot",
      "path": "/opt/samples/corpus/binaries/98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648/challenge63.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 767,
          "length": 9,
          "xor_key": null
        },
        {
          "id": "$d2",
          "offset": 777,
          "length": 10,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 82718,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "keylogger",
      "path": "/opt/samples/corpus/binaries
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
