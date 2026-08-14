# Technical Evidence Pack

**sha256:** 0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc  
**sample_path:** /opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 95
- **family_guess**: Tibs
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA agree on import DLLs (ntdll, shlwapi, wininet, shell32, kernel32, user32, advapi32, ole32) and the presence of 'Adware.dll' string. MalCat identifies high-entropy sections, XOR loops, and behavioral imports (InternetOpen, RegSetValue, CreateProcess, VirtualAlloc). Capa and YARA provide direct behavioral rules (process injection, privilege escalation, anti-VM). External TI (VirusTotal) reports 58/70 malicious detections with threat label 'trojan.tibs/gen2'.
- **summary**: This DLL is a packed and obfuscated trojan downloader (Tibs family) that performs process injection, privilege escalation, and network communication via WinINet APIs. It uses XOR encryption (key 0x5d785e) and anti-VM techniques to evade analysis. Key behavioral indicators include imports for registry manipulation, process creation, memory allocation, and token adjustment, supported by YARA rules for injection and escalation. External VirusTotal reports high detection rates (58/70). The high entropy (7.99), unusual sections (.nasoc, .tlsc), and unreferenced imports suggest packing/obfuscation, but the behavioral evidence confirms malicious intent.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | malcat_evidence | `ProcessInjectionTargets` | YARA rule matching process injection targets, indicating malicious intent for code injection. |
| malcat | malcat_evidence | `ElevatePrivileges` | YARA rule matching privilege escalation, a common malicious behavior. |
| malcat | anomalies | `XorInLoop` | XOR operations in loops at addresses 7008, 7021, 7187, indicating data decryption/obfuscation. |
| malcat | decompilations | `sub_100027e5` | Decompilation shows XOR loop with key 0x5d785e, a clear decryption routine. |
| malcat | top high-signal imports | `wininet.InternetReadFile` | Network communication import for C2/beaconing. |
| malcat | top high-signal imports | `advapi32.AdjustTokenPrivileges` | Token manipulation for privilege escalation. |
| malcat | top high-signal imports | `kernel32.VirtualAlloc` | Memory allocation for code injection or shellcode. |
| capa | capa rules | `reference anti-VM strings targeting Xen` | Anti-analysis technique to evade virtualization sandboxes (T1497.001). |
| floss | strings | `InternetOpenUrlA` | Indicates network communication capability. |
| floss | strings | `Software\` | Registry key for persistence or configuration. |
| external_ti | VirusTotal | `malicious=58` | 58/70 AV detections as malicious with threat label 'trojan.tibs/gen2'. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The DLL file hubert.dll matches multiple YARA rules indicative of malware, including privilege escalation, registry and file system manipulation, network communication via WinInet APIs, and obfuscation through packing and base64 encoding. Credential access techniques were not observed in hubert.dll {tool_output, capability_scan, credential_access_domain, no indicators found}. The entry point of the DLL did not show evidence of malicious propagation methods {static_analysis, entry_point_analysis, dll_main, no malicious code at entry}. Import analysis revealed the use of system APIs from kernel32.dll and advapi32.dll, which are frequently exploited in malware operations {import_table, api_imports, suspicious_apis, facilitates file, registry, and network activities}.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "escalate_priv", "row_or_rule": "matched strings at offsets 14078 and 14016", "why": "Contains strings associated with privilege escalation techniques, a common malicious behavior"}`
- `{"source": "checklist_yara_scan", "query_or_table": "win_registry", "row_or_rule": "multiple string matches at various offsets", "why": "Indicates extensive registry manipulation for persistence, configuration, or malicious activity"}`
- `{"source": "checklist_yara_scan", "query_or_table": "Str_Win32_Internet_API", "row_or_rule": "matched API calls like InternetOpen and HttpSendRequest", "why": "Demonstrates network communication capabilities, suggesting command and control or data exfiltration"}`
- `{"source": "checklist_yara_scan", "query_or_table": "contains_base64", "row_or_rule": "matched base64 string at offset 10822", "why": "May contain obfuscated malicious payloads or data encoded to evade detection"}`
- `{"source": "checklist_yara_scan", "query_or_table": "Microsoft_Visual_Basic_v50", "row_or_rule": "signature match at offset 79", "why": "Indicates development in Visual Basic v5.0, which is sometimes used in malware for its scripting capabilities"}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc
size: 323584
type: PE
architecture: X86
entrypoint_ea: 6943
entropy: 7.99
file_name: hubert.dll
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 36 | - |
| .text | 1024 | 8192 | 8192 | 224 | RX |
| .rdata | 9216 | 5120 | 8192 | 88 | R |
| .data | 17408 | 1024 | 4096 | 0 | RW |
| .tlsc | 21504 | 304128 | 307200 | 226 | R |
| .nasoc | 328704 | 4096 | 4096 | 225 | WX |

### Malcat YARA / Signatures (4)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2005_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| ProcessInjectionTargets | evasion | UNCOMMON | 20 | contains a list of process names often used as injection target in Windows |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |

### Anomalies (9)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ExecutableSectionNoCode | 4 | sections | 1 | executable section has the flag code not set |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 9 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| DllNoRelocation | 3 | sections | 1 | dll has no relocation information |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 79 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 3 | XOR instruction in a loop |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |

### Anomaly Locations (high-signal)
- **XorInLoop**
  - `7008`: 
  - `7021`: 
  - `7187`: 

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 13600 | `KERNEL32.dll` |
| 13020 | `CreateMutexW` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 12080 | `\Internet Explorer\iexplore.exe` |
| 11960 | `explorer.exe` |
| 12846 | `InternetReadFile` |
| 14016 | `AdjustTokenPrivileges` |
| 12756 | `ntdll.dll` |
| 12902 | `WININET.dll` |
| 14128 | `ole32.dll` |
| 14210 | `Adware.dll` |
| 12986 | `SHELL32.dll` |
| 14078 | `ADVAPI32.dll` |
| 13600 | `KERNEL32.dll` |
| 13890 | `USER32.dll` |
| 12812 | `SHLWAPI.dll` |
| 11584 | `System files of ..our system ASAP.` |
| 11216 | `a=gg0<45(7a=0(1=..156(=56`a70`26gf` |
| 10600 | `D%v`fpwlq|%qmw`d..b`%qj%w`hjs`%lq+` |
| 9904 | `Mdwhcpi%slwpv`v%..c%|jpw%fjhupq`w+` |
| 10264 | `Lq%lv%vqwjkbi|%w..c%|jpw%fjhupq`w+` |
| 10408 | `Lq%lv%vqwjkbi|%w..c%|jpw%fjhupq`w+` |
| 10064 | `\jp%dw`%wpkklkb%..c%|jpw%fjhupq`w+` |
| 9736 | `D%v`fpwlq|%qmw`d..c%|jpw%fjhupq`w+` |
| 10992 | `Mdwhcpi%slwpv`v%..mw`dqv%cjw%cw``+` |
| 10770 | ``a%u`wvjk%qwl`v%..%la`kqlq|%qm`cq+` |
| 11880 | `Vjcqrdw`YYHlfwjv..Ujilfl`vYYV|vq`h` |
| 14221 | `_Run@0` |
| 10899 | ``a%dff`vv%qj%|jp..lslwpv%vjcqrdw`+` |
| 11776 | `\_favdata.dat` |
| 11800 | `mqqu?** v*w`daad..vljk8 v#dardw`jn` |
| 12028 | `24d1ca9a-a864-4f..6fe-495eb56529d8` |
| 11988 | `dd1c3e54-4b10-4a..1eb-fa561c094261` |
| 11292 | `<1=51=354163<276..<160<255<2245757` |
| 12156 | `SeShutdownPrivilege` |
| 11120 | `A`c`kv`%F`kq`w` |
| 11376 | `\license.dat` |
| 11456 | `fjiesogjfoerajgoasj` |
| 13212 | `DisableThreadLibraryCalls` |
| 13112 | `InitializeCriticalSection` |
| 13274 | `DeleteCriticalSection` |
| 11748 | `Printers\Connections` |
| 118562 | `0.sjE` |
| 12196 | `fiuejsiogj` |
| 13492 | `GetFileAttributesA` |
| 131627 | `h.bDy` |
| 77 | `!This program ca..in DOS mode.
$` |
| 313532 | `R.hCi` |
| 11532 | `YYqwjo555+`}`` |
| 14110 | `CoCreateInstance` |
| 12826 | `InternetOpenUrlA` |
| 13770 | `TranslateMessage` |
| 12882 | `InternetCloseHandle` |
| 11504 | `YYvudh556+`}`` |
| 12866 | `InternetOpenA` |
| 11476 | `YYvudh554+`}`` |
| 13442 | `GetCurrentProcess` |
| 14040 | `InitiateSystemShutdownW` |
| 9668 | `ujwkjqpg`+fjh` |
| 13140 | `GetVolumeInformationA` |
| 11188 | `rvfvsf67+`}`` |
| 13978 | `LookupPrivilegeValueW` |
| 9640 | `kpa`qpg`+fjh` |
| 13904 | `OpenProcessToken` |
| 12916 | `SHGetSpecialFolderPathA` |
| 12942 | `SHGetSpecialFolderPathW` |
| 12768 | `StrStrIA` |
| 13858 | `CreateDialogParamA` |
| 68379 | `fQXQQ` |
| 13750 | `IsDialogMessageW` |
| 13298 | `CreateThread` |
| 11340 | `A`c`kv`%F`kq`w` |
| 13424 | `CreateProcessW` |
| 13374 | `SetFilePointer` |
| 9616 | `|jpujwk+fjh` |
| 13616 | `DispatchMessageW` |
| 182012 | `z4.fAy` |
| 13326 | `GetTempFileNameW` |
| 13000 | `GetComputerNameA` |
| 14140 | `memset` |
| 13240 | `GetModuleFileNameA` |
| 318360 | `X0HXCHW` |
| 13020 | `CreateMutexW` |

### Constants / Known Patterns (2)
| Category | Value |
|---|---|
| guid | `guid::IShellLinkW` |
| guid | `guid::IPersistFile` |

### Imports (80)
| EA | Name | Type | Refs |
|---|---|---|---|
| 7280 | _Run@0 | EXPORT | 1 |
| 9216 | advapi32.RegCloseKey | IMPORT | 4 |
| 9220 | advapi32.InitiateSystemShutdownW | IMPORT | 0 |
| 9224 | advapi32.AdjustTokenPrivileges | IMPORT | 0 |
| 9228 | advapi32.RegOpenKeyA | IMPORT | 0 |
| 9232 | advapi32.LookupPrivilegeValueW | IMPORT | 0 |
| 9236 | advapi32.RegCreateKeyA | IMPORT | 0 |
| 9240 | advapi32.RegQueryValueExA | IMPORT | 0 |
| 9244 | advapi32.RegSetValueExA | IMPORT | 0 |
| 9248 | advapi32.OpenProcessToken | IMPORT | 0 |
| 9256 | kernel32.CloseHandle | IMPORT | 1 |
| 9260 | kernel32.LockResource | IMPORT | 0 |
| 9264 | kernel32.VirtualAlloc | IMPORT | 0 |
| 9268 | kernel32.GetLastError | IMPORT | 0 |
| 9272 | kernel32.CreateFileW | IMPORT | 0 |
| 9276 | kernel32.GetComputerNameA | IMPORT | 0 |
| 9280 | kernel32.CreateMutexW | IMPORT | 0 |
| 9284 | kernel32.lstrlenA | IMPORT | 0 |
| 9288 | kernel32.lstrcpynA | IMPORT | 0 |
| 9292 | kernel32.WaitForSingleObject | IMPORT | 0 |
| 9296 | kernel32.GetTickCount | IMPORT | 0 |
| 9300 | kernel32.VirtualFree | IMPORT | 0 |
| 9304 | kernel32.InitializeCriticalSection | IMPORT | 0 |
| 9308 | kernel32.GetVolumeInformationA | IMPORT | 0 |
| 9312 | kernel32.Sleep | IMPORT | 0 |
| 9316 | kernel32.lstrcatA | IMPORT | 0 |
| 9320 | kernel32.lstrlenW | IMPORT | 0 |
| 9324 | kernel32.GetTempPathW | IMPORT | 0 |
| 9328 | kernel32.DisableThreadLibraryCalls | IMPORT | 0 |
| 9332 | kernel32.GetModuleFileNameA | IMPORT | 0 |
| 9336 | kernel32.lstrcatW | IMPORT | 0 |
| 9340 | kernel32.DeleteCriticalSection | IMPORT | 0 |
| 9344 | kernel32.CreateThread | IMPORT | 0 |
| 9348 | kernel32.lstrcpyA | IMPORT | 0 |
| 9352 | kernel32.GetTempFileNameW | IMPORT | 0 |
| 9356 | kernel32.CreateFileA | IMPORT | 0 |
| 9360 | kernel32.GetFileSize | IMPORT | 0 |
| 9364 | kernel32.SetFilePointer | IMPORT | 0 |
| 9368 | kernel32.FindResourceW | IMPORT | 0 |
| 9372 | kernel32.LoadResource | IMPORT | 0 |
| 9376 | kernel32.CreateProcessW | IMPORT | 0 |
| 9380 | kernel32.GetCurrentProcess | IMPORT | 0 |
| 9384 | kernel32.WriteFile | IMPORT | 0 |
| 9388 | kernel32.ReadFile | IMPORT | 0 |
| 9392 | kernel32.SizeofResource | IMPORT | 0 |
| 9396 | kernel32.GetFileAttributesA | IMPORT | 0 |
| 9404 | shell32.Shell_NotifyIconA | IMPORT | 1 |
| 9408 | shell32.SHGetSpecialFolderPathW | IMPORT | 0 |
| 9412 | shell32.SHGetSpecialFolderPathA | IMPORT | 0 |
| 9420 | shlwapi.StrCatW | IMPORT | 1 |
| 9424 | shlwapi.wnsprintfA | IMPORT | 0 |
| 9428 | shlwapi.StrCpyW | IMPORT | 0 |
| 9432 | shlwapi.StrStrIA | IMPORT | 0 |
| 9440 | user32.DispatchMessageW | IMPORT | 1 |
| 9444 | user32.FindWindowA | IMPORT | 0 |
| 9448 | user32.SendMessageW | IMPORT | 0 |
| 9452 | user32.PostMessageA | IMPORT | 0 |
| 9456 | user32.IsWindow | IMPORT | 0 |
| 9460 | user32.ShowWindow | IMPORT | 0 |
| 9464 | user32.EndDialog | IMPORT | 0 |
| 9468 | user32.GetWindowTextW | IMPORT | 0 |
| 9472 | user32.LoadIconW | IMPORT | 0 |
| 9476 | user32.IsDialogMessageW | IMPORT | 0 |
| 9480 | user32.TranslateMessage | IMPORT | 0 |
| 9484 | user32.EnumWindows | IMPORT | 0 |
| 9488 | user32.wsprintfA | IMPORT | 0 |
| 9492 | user32.KillTimer | IMPORT | 0 |
| 9496 | user32.PostMessageW | IMPORT | 0 |
| 9500 | user32.GetMessageW | IMPORT | 0 |
| 9504 | user32.CreateDialogParamA | IMPORT | 0 |
| 9508 | user32.SetTimer | IMPORT | 0 |
| 9516 | wininet.InternetReadFile | IMPORT | 1 |
| 9520 | wininet.InternetOpenA | IMPORT | 0 |
| 9524 | wininet.InternetCloseHandle | IMPORT | 0 |
| 9528 | wininet.InternetOpenUrlA | IMPORT | 0 |
| 9536 | ntdll.atol | IMPORT | 1 |
| 9540 | ntdll.memset | IMPORT | 0 |
| 9544 | ntdll._chkstk | IMPORT | 0 |
| 9552 | ole32.CoInitialize | IMPORT | 1 |
| 9556 | ole32.CoCreateInstance | IMPORT | 0 |

### Functions (7)
| EA | Name |
|---|---|
| 6985 | sub_10002749 |
| 7141 | sub_100027e5 |
| 6943 | EntryPoint |
| 7280 | _Run@0 |
| 7127 | sub_100027d7 |
| 7117 | sub_100027cd |
| 7124 | sub_100027d4 |

### Decompilations (top 6)
#### 6985 — sub_10002749
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_10002749(undefined4 param_1,char *param_2)

{
    char *extraout_EDX;
    int32_t iVar1;
    bool bVar2;
    undefined4 uVar3;
    
    uVar3 = 0;
    do {
        do {
            bVar2 = *param_2 == 'M';
            func_0x100027b8(uVar3);
            param_2 = extraout_EDX;
        } while (!bVar2);
    } while (extraout_EDX[0x1001] != 'Z');
    sub_100027d7(&stack0xfffffffc);
    iVar1 = 0x10589;
    do {
        iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    sub_100027e5();
    return;
}

```
#### 7141 — sub_100027e5
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_100027e5(int32_t param_1)

{
    int32_t iVar1;
    int32_t *unaff_ESI;
    int32_t *unaff_EDI;
    
    do {
        iVar1 = 0x11589;
        do {
            iVar1 = iVar1 + -1;
        } while (iVar1 != 0);
        *unaff_EDI = ROUND(ROUND(*unaff_ESI) ^ 0x5d785e);
        unaff_ESI = unaff_EDI + 1;
        param_1 = param_1 + -1;
        unaff_EDI = unaff_ESI;
    } while (param_1 != 0);
    return;
}

```
#### 6943 — EntryPoint
```c

/* WARNING (jumptable): Unable to track spacebase fully for stack */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 EntryPoint(void)

{
    undefined4 uVar1;
    code *UNRECOVERED_JUMPTABLE;
    int32_t unaff_retaddr;
    
    if (unaff_retaddr == 0x75000000) {
        return 0x10000;
    }
    sub_10002749();
    /* WARNING: Could not recover jumptable at 0x100027d2. Too many branches */
    /* WARNING: Treating indirect jump as call */
    uVar1 = (*UNRECOVERED_JUMPTABLE)();
    return uVar1;
}

```

### Structures (27)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 216 |
| OptionalHeader | 240 |
| Sections | 464 |
| advapi32.FT | 9216 |
| kernel32.FT | 9256 |
| shell32.FT | 9404 |
| shlwapi.FT | 9420 |
| user32.FT | 9440 |
| wininet.FT | 9516 |
| ntdll.FT | 9536 |
| ole32.FT | 9552 |
| ImportTable | 12220 |
| advapi32.OFT | 12400 |
| kernel32.OFT | 12440 |
| shell32.OFT | 12588 |
| shlwapi.OFT | 12604 |
| user32.OFT | 12624 |
| wininet.OFT | 12700 |
| ntdll.OFT | 12720 |
| ole32.OFT | 12736 |
| ImportNames | 12748 |
| ExportDirectory | 14160 |
| ExportAddressTable | 14200 |
| ExportNameTable | 14204 |
| OrdinalNameTable | 14208 |
| ExportNames | 14210 |


## capa Capability Rules
engine: `capa` · Total rules: 3 · duration_s: 1.19

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| reference anti-VM strings targeting Xen | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| contain loop |  |  |

## PE Imports / Signals
import_count: 79

| label | api_match | ATT&CK |
|---|---|---|
| http_client | InternetOpen | T1071.001 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 16

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@31943 len=2 |
| contains_base64 | - | $a@10822 len=12 |
| Browsers | - | $ie@12118 len=24 |
| IsPE32 | - |  |
| IsDLL | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| Microsoft_Visual_Basic_v50 | - | $a@79 len=1 |
| escalate_priv | - | $d1@14078 len=12; $c2@14016 len=21 |
| win_mutex | - | $c1@13020 len=11 |
| win_registry | - | $f1@14078 len=12; $c1@13942 len=16; $c3@14066 len=11; $c4@13924 len=14; $c5@13962 len=13; $c6@14066 len=11 |
| win_token | - | $f1@14078 len=12; $c2@14016 len=21; $c3@13904 len=16 |
| win_files_operation | - | $f1@13600 len=12; $c1@13462 len=9; $c2@13374 len=14; $c3@13462 len=9; $c4@12854 len=8; $c6@13346 len=11 |
| Str_Win32_Wininet_Library | - | $wininet_lib@12902 len=11 |
| Str_Win32_Internet_API | - | $wininet_call_closeh@12882 len=19; $wininet_call_readf@12846 len=16; $wininet_call_open@12826 len=12 |

## Generated YARA Meta
```json
{
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 31943,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 10822,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Browsers",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$ie",
          "offset": 12118,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
      "rule": "escalate_priv",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$d1",
          "offset": 14078,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 14016,
          "length": 21,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$c1",
          "offset": 13020,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_registry",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$f1",
          "offset": 14078,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 13942,
          "length": 16,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 14066,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 13924,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 13962,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 14066,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_token",
  
```

## FLOSS Strings
Total strings: 695 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 695}`

### High-signal FLOSS
- `CreateMutexW`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `@.nasoc`
- `v^r6ws`
- `1xyzkXz`
- `O$] C;`
- `{"[lOO`
- `|xz{.#`
- `]/o'EY`
- `So/"9I`
- `"OjS#0`
- `PC"oP7`
- `:[A3OE`
- `sxDzk-`
- `D%v`fpwlq|%qmw`dq%a`q`fq`a%jk%|jpw%fjhupq`w$%Qmlv%hdilfljpv%uwjbwdh%hd|%vq`di%|jpw%uwlsdq`%adqd+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+`
- `Mdwhcpi%slwpv`v%a`q`fq`a%jk%|jpw%fjhupq`w+%Qmlv%hdilfljpv%vjcqrdw`%hd|%mdwh%|jpw%fjhupq`w+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+`
- `\jp%dw`%wpkklkb%d%qwldi%dkqlslwpv%vjcqrdw`%s`wvljk+%Dfqlsdq`%|jpw%dkqlslwpv%vjcqrdw`%fju|%qj%b`q%cpii(qlh`%dkqlslwpv%uwjq`fqljk+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+`
- `Lq%lv%vqwjkbi|%w`fjhh`ka`a%qj%uwjq`fq%|jpw%fjhupq`w%dbdlkvq%v`fpwlq|%qmw`dqv+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+`
- `Lq%lv%vqwjkbi|%w`fjhh`ka`a%qj%w`hjs`%dii%a`q`fq`a%slwpv`v%qj%uwjq`fq%|jpw%fjhupq`w%dbdlkvq%`}lvqlkb%v`fpwlq|%qmw`dqv+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+`
- `Adkb`w$`
- `D%v`fpwlq|%qmw`dq%a`q`fq`a%jk%|jpw%fjhupq`w+%QwjodkDVU]+OV+Rlk67+%Lq%vqwjkbi|%w`fjhh`ka`a%qj%w`hjs`%qmlv%qmw`dq%wlbmq%kjr+%Filfn%jk%qm`%h`vvdb`%qj%w`hjs`%lq+`
- `Pkdpqmjwl`
- ``a%u`wvjk%qwl`v%qj%vq`di%|jpw%udvvrjwav%dka%uwlsdq`%lkcjwhdqljk+%Filfn%jk%qm`%h`vvdb`%qj%uw`s`kq%la`kqlq|%qm`cq+`
- `Pkdpqmjvwl`
- ``a%dff`vv%qj%|jpw%fjhupq`w$%Filfn%jk%qm`%h`vvdb`%qj%lkvqdii%pu(qj(adq`%dkqlslwpv%vjcqrdw`+`
- `Mdwhcpi%slwpv`v%a`q`fq`a%jk%|jpw%fjhupq`w+%Filfn%jk%qm`%h`vvdb`%qj%vfdk%|jpw%fjhupq`w%cjw%v`fpwlq|%qmw`dqv%cjw%cw``+`
- `<1=51=354163<2766<6<<2062567<160<255<2245757`
- `A`c`kv`%F`kq`w`
- `Software\`
- `License`
- `\license.dat`
- `a`cfkq+`}``
- `Windows Security Alert`
- `fjiesogjfoerajgoasj`
- `Shell_TrayWnd`
- `Button`
- `Printers\Connections`
- `\_favdata.dat`
- `mqqu?** v*w`daadqdbdq`rd|+umu:q|u`8vqdqv#dccla8 v#vpgla8 v#s`wvljk8 v#dardw`jn`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x1000271f
```asm
┌ 49: entry0 ();
│           0x1000271f      68ffff0000     push 0xffff
│           0x10002724      0fae1424       ldmxcsr dword [esp]
│           0x10002728      58             pop eax
│           0x10002729      6a00           push 0
│           0x1000272b      0fae1c24       stmxcsr dword [esp]
│           0x1000272f      58             pop eax
│           0x10002730      40             inc eax
│           0x10002731      8d905244ff00   lea edx, [eax + 0xff4452]
│           0x10002737      8b1424         mov edx, dword [esp]
│           0x1000273a      4a             dec edx
│           0x1000273b      81faffffff74   cmp edx, 0x74ffffff
│       ┌─< 0x10002741      0f8586000000   jne 0x100027cd
│       │   0x10002747      c9             leave
│       │   0x10002748      c3             ret
        │   ; CALL XREF from entry0 @ 0x100027cd(x)
..
        │   ; CALL XREF from fcn.10002749 @ 0x10002766(x)
│       └─> 0x100027cd      e877ffffff     call fcn.10002749
└           0x100027d2      ffe2           jmp edx
```
### 0x10002749
```asm
; CALL XREF from entry0 @ 0x100027cd(x)
┌ 111: fcn.10002749 (int32_t arg_10h);
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_10h @ esp+0x20
│           0x10002749      55             push ebp
│           0x1000274a      89e5           mov ebp, esp
│           0x1000274c      83ec04         sub esp, 4
│           0x1000274f      c745fc0000..   mov dword [var_4h], 0
│           0x10002756      660f12442410   movlpd xmm0, qword [arg_10h]
│           0x1000275c      660f7ec2       movd edx, xmm0
│      ┌┌─> 0x10002760      8a02           mov al, byte [edx]
│      ╎╎   0x10002762      34ce           xor al, 0xce                ; 206
│      ╎╎   0x10002764      3c83           cmp al, 0x83                ; 131
│      ╎╎   0x10002766      e84d000000     call fcn.100027b8
│      └──< 0x1000276b      75f3           jne 0x10002760
│       ╎   0x1000276d      8a8201100000   mov al, byte [edx + 0x1001]
│       ╎   0x10002773      34be           xor al, 0xbe                ; 190
│       ╎   0x10002775      3ce4           cmp al, 0xe4                ; 228
│       └─< 0x10002777      75e7           jne 0x10002760
│           0x10002779      81c200202100   add edx, 0x212000
│           0x1000277f      f8             clc
│           0x10002780      81ea00102100   sub edx, 0x211000
│           0x10002786      56             push esi
│           0x10002787      57             push edi
│           0x10002788      53             push ebx
│           0x10002789      55             push ebp
│           0x1000278a      e848000000     call fcn.100027d7
│           0x1000278f      31f6           xor esi, esi
│           0x10002791      ba89050100     mov edx, 0x10589
│       ┌─> 0x10002796      b800160500     mov eax, 0x51600
│       ╎   0x1000279b      89c6           mov esi, eax
│       ╎   0x1000279d      83ea01         sub edx, 1
│       ╎   0x100027a0      85d2           test edx, edx
│       └─< 0x100027a2      75f2           jne 0x10002796
│           0x100027a4      01ee           add esi, ebp
│           0x100027a6      89f7           mov edi, esi
│           0x100027a8      e838000000     call fcn.100027e5
│           0x100027ad      f7db           neg ebx
│           0x100027af      8d149e         lea edx, [esi + ebx*4]
│           0x100027b2      5d             pop ebp
│           0x100027b3      5b             pop ebx
│           0x100027b4      5f             pop edi
│           0x100027b5      5e             pop esi
│           0x100027b6      c9             leave
└           0x100027b7      c3             ret
```
### 0x100027b8
```asm
; CALL XREF from fcn.10002749 @ 0x10002766(x)
┌ 21: fcn.100027b8 ();
│           ; var int32_t var_14h @ esp+0x14
│           0x100027b8      60             pushal
│           0x100027b9      89d0           mov eax, edx
│           0x100027bb      8d8000f0ffff   lea eax, [eax - 0x1000]
│           0x100027c1      660f6ec8       movd xmm1, eax
│           0x100027c5      660f7e4c2414   movd dword [var_14h], xmm1
│           0x100027cb      61             popal
└           0x100027cc      c3             ret
```
### 0x100027d7
```asm
; CALL XREF from fcn.10002749 @ 0x1000278a(x)
┌ 14: fcn.100027d7 ();
│           0x100027d7      89d5           mov ebp, edx
│           0x100027d9      29c0           sub eax, eax
│           0x100027db      8d8c005002..   lea ecx, [eax + eax + 0x250]
│           0x100027e2      89cb           mov ebx, ecx
└           0x100027e4      c3             ret
```
### 0x100027e5
```asm
; CALL XREF from fcn.10002749 @ 0x100027a8(x)
┌ 73: fcn.100027e5 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           0x100027e5      55             push ebp
│           0x100027e6      89e5           mov ebp, esp
│           0x100027e8      83ec08         sub esp, 8
│           0x100027eb      c745f80000..   mov dword [var_8h], 0
│           0x100027f2      c745fc0000..   mov dword [var_4h], 0
│       ┌─> 0x100027f9      ba89150100     mov edx, 0x11589
│      ┌──> 0x100027fe      0f59d3         mulps xmm2, xmm3
│      ╎╎   0x10002801      9b             wait
│      ╎╎   0x10002802      dbe3           fninit
│      ╎╎   0x10002804      db06           fild dword [esi]
│      ╎╎   0x10002806      db55f8         fist dword [ebp - 8]
│      ╎╎   0x10002809      8b45f8         mov eax, dword [var_8h]
│      ╎╎   0x1000280c      83ea01         sub edx, 1
│      ╎╎   0x1000280f      85d2           test edx, edx
│      └──< 0x10002811      75eb           jne 0x100027fe
│       ╎   0x10002813      355e785d00     xor eax, 0x5d785e
│       ╎   0x10002818      8945f8         mov dword [var_8h], eax
│       ╎   0x1000281b      db45f8         fild dword [ebp - 8]
│       ╎   0x1000281e      db17           fist dword [edi]
│       ╎   0x10002820      b804000000     mov eax, 4
│       ╎   0x10002825      8d3c07         lea edi, [edi + eax]
│       ╎   0x10002828      89fe           mov esi, edi
│       └─< 0x1000282a      e2cd           loop 0x100027f9
│           0x1000282c      c9             leave
└           0x1000282d      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r

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
  - `ntdll.dll!atol`
  - `ntdll.dll!memset`
  - `ntdll.dll!_chkstk`
  - `SHLWAPI.dll!StrCatW`
  - `SHLWAPI.dll!wnsprintfA`
  - `SHLWAPI.dll!StrCpyW`
  - `SHLWAPI.dll!StrStrIA`
  - `WININET.dll!InternetReadFile`
  - `WININET.dll!InternetOpenA`
  - `WININET.dll!InternetCloseHandle`
  - `WININET.dll!InternetOpenUrlA`
  - `SHELL32.dll!Shell_NotifyIconA`
  - `SHELL32.dll!SHGetSpecialFolderPathW`
  - `SHELL32.dll!SHGetSpecialFolderPathA`
  - `KERNEL32.dll!CloseHandle`
  - `KERNEL32.dll!LockResource`
  - `KERNEL32.dll!VirtualAlloc`
  - `KERNEL32.dll!GetLastError`
  - `KERNEL32.dll!CreateFileW`
  - `USER32.dll!DispatchMessageW`
  - `USER32.dll!FindWindowA`
  - `USER32.dll!SendMessageW`
  - `USER32.dll!PostMessageA`
  - `USER32.dll!IsWindow`
  - `ADVAPI32.dll!RegCloseKey`
  - `ADVAPI32.dll!InitiateSystemShutdownW`
  - `ADVAPI32.dll!AdjustTokenPrivileges`
  - `ADVAPI32.dll!RegOpenKeyA`
  - `ADVAPI32.dll!LookupPrivilegeValueW`
  - `ole32.dll!CoInitialize`
