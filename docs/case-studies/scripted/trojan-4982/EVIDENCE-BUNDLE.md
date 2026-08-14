# Technical Evidence Pack

**sha256:** 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73  
**sample_path:** /opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe  
**project_name:** day6

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: Trioris
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple tools detect anti-debugging, network communication, data theft, and obfuscation. Ghidra, IDA, and MalCat confirm PE structure and anomalies. Capa identifies behavioral intent (credit card parsing, C2). VirusTotal shows high detection rate (55/72) with threat family 'Trioris/Cerbu'.
- **summary**: The sample is a PE x86 executable exhibiting multiple malicious behaviors: anti-debugging (IsDebuggerPresent, anti_dbg YARA), process creation and memory manipulation (CreateProcess, VirtualAlloc, VirtualProtect), network communication (send/receive data, DNS resolution, HTTP User-Agent), and data theft (credit card parsing). Obfuscation techniques (XorInLoop, DynamicString) are present but considered neutral alone; however, combined with behavioral indicators, they support malicious intent. VirusTotal reports 55/72 detections with threat family 'Trioris/Cerbu'. The sample is signed with an invalid signature, further raising suspicion.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | pe_imports signals | `check_debugger (IsDebuggerPresent)` | Anti-debugging capability, common in malware to evade analysis. |
| pe_imports | pe_imports signals | `create_process (CreateProcess)` | Ability to create new processes, often used for process injection or launching malicious payloads. |
| pe_imports | pe_imports signals | `allocate_memory (VirtualAlloc)` | Dynamic memory allocation, common in code injection or unpacking. |
| pe_imports | pe_imports signals | `change_memory_protection (VirtualProtect)` | Changing memory protection to execute injected code or modify existing code. |
| capa | capa rules | `parse credit card information` | Indicates data theft targeting financial information, a clear malicious intent. |
| capa | capa rules | `send data` | Network communication capability for data exfiltration or C2. |
| capa | capa rules | `receive data` | Network communication capability for command and control. |
| capa | capa rules | `resolve DNS` | Network communication for domain resolution, typical of C2 infrastructure. |
| capa | capa rules | `reference HTTP User-Agent string` | HTTP communication, likely for command and control or data exfiltration. |
| yara | YARA matches | `anti_dbg` | Anti-debugging technique detected, indicating evasion. |
| external TI | VirusTotal | `55/72 detections, threat family trioris/cerbu` | High detection rate and identified threat family confirm malicious nature. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This PE is a trojan with HTTP-based C2 communication to the Russian domain 'twoyden.ru', SOCKS5 proxy/relay capability, system fingerprinting (VM detection, OS info), registry persistence via 'Software\ClearSystem', anti-debug checks, RC4/XOR encryption, obfuscated stack strings, and privilege escalation via requireAdministrator manifest. It masquerades its User-Agent as 'NSISDL/1.2' while conducting HTTP POST/GET requests with full proxy awareness. Exfiltration is supported via HTTP POST requests to 'twoyden.ru' for data sending {Network_traffic_analysis, HTTP_POST_requests, twoyden.ru, exfiltration_capability}. Credential access techniques were not observed in the analysis {Dynamic_analysis, API_calls, absence_of_credential_functions, not_observed}.

### deep key_evidence
- `"Domain 'twoyden.ru' referenced in FUN_00409aa5 (Ghidra string_refs, addr 0x00409aa5)"`
- `"HTTP/1.1 C2 communication with POST method, Host/Content-Type/Content-Length headers in FUN_004060ce (Ghidra string_refs)"`
- `"User-Agent: NSISDL/1.2 spoofing in FUN_004060ce to disguise C2 traffic as NSIS downloader (Ghidra strings, addr 4357332)"`
- `"Custom 'My-User-Agent:' header in FUN_0040aac8 (Ghidra string_refs, addr 0x0040aac8)"`
- `"Registry persistence via 'Software\\ClearSystem' keys with 'value_vm' and 'value_os' values (FUN_0040399b, FUN_00403a25)"`
- `"System fingerprinting: reads InstallDate from SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion, stores OS/VM info (Ghidra string_refs FUN_00403a25)"`
- `"Build/config string '/S pid=129 subid=10 mr=0 lang=ru' indicating Russian-locale targeting (Ghidra strings, addr 4359000)"`
- `"SOCKS5 proxy relay capability: 'socks' string present (Ghidra strings, addr 4356372), full WSA socket APIs (WSAConnect, WSASocketA, WSASend, WSARecv, WSAEventSelect)"`
- `"Proxy-aware HTTP: reads ProxyServer/ProxyOverride from Internet Settings registry, handles proxy-authenticate/www-authenticate responses (FUN_004095b5, FUN_0040791d)"`
- `"Anti-debug: IsDebuggerPresent import (pe_import_signals T1622), YARA anti-debug rule matches at offsets 169872/170594/169284"`
- `"Capa: obfuscated stackstrings (T1027.005), XOR encoding (T1027/C0026.002), RC4 KSA encryption (C0027.009/C0028.002)"`
- `"requireAdministrator manifest requesting elevated privileges (Ghidra strings, addr 4396736)"`
- `"Code injection capability: VirtualAlloc + VirtualProtect imports (pe_import_signals T1055), CreateProcessW for child process spawning"`
- `"Dynamic API resolution via LoadLibraryExW + GetProcAddress (pe_import_signals T1129)"`
- `"31 capa rules matched including network communication, file discovery, registry operations, process creation, and anti-analysis techniques"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73
size: 235184
type: PE
architecture: X86
entrypoint_ea: 57943
entropy: 6.82
file_name: trojan_4982.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 32 | - |
| .text | 1024 | 133632 | 135168 | 140 | RX |
| .rdata | 136192 | 37376 | 40960 | 74 | R |
| .data | 177152 | 8704 | 20480 | 58 | RW |
| .rsrc | 197632 | 2560 | 4096 | 111 | R |
| .reloc | 201728 | 7680 | 8192 | 123 | R |
| overlay | 209920 | 44208 | 0 | 186 | - |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2013_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| ChangeBrowserPreference | tampering | SUSPICIOUS | 40 | may change browser preference, often used by adware |

### Anomalies (7)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| BigStringHiScore | 3 | strings | 1 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 1 | string is constructed dynamically |
| ManyUniqueImmediateBytes | 3 | code | 5 | More than 48 unique bytes defined across all immediate operands in the function |
| XorInLoop | 3 | code | 16 | XOR instruction in a loop |
| SequentialFunction | 1 | code | 1 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 8 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `45699`: 
- **ManyUniqueImmediateBytes**
  - `36517`: 
  - `43059`: 
  - `70759`: 
  - `80356`: 
  - `86490`: 
- **SequentialFunction**
  - `43059`: 
- **SpaghettiFunction**
  - `47820`: 
  - `48208`: 
  - `51620`: 
  - `56007`: 
  - `83695`: 
- **XorInLoop**
  - `11571`: 
  - `30154`: 
  - `30274`: 
  - `30410`: 
  - `59776`: 

### High-Signal Strings (15 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 143296 | `kernel32.dll` |
| 156960 | `GetProcessWindowStation` |
| 159796 | ` HTTP/1.1
` |
| 171408 | `KERNEL32.dll` |
| 246662 | `Ehttp://www.micr.._2011-10-19.crt0` |
| 246565 | `Chttp://www.micr..2011-10-19.crl0a` |
| 247827 | `Ehttp://crl.micr..2010-06-23.crl0Z` |
| 250370 | `Ehttp://crl.micr..2010-06-23.crl0Z` |
| 252000 | `Ehttp://crl.micr..2010-07-01.crl0Z` |
| 247926 | `>http://www.micr..2010-06-23.crt0` |
| 250469 | `>http://www.micr.._2010-06-23.crt0` |
| 252099 | `>http://www.micr.._2010-07-01.crt0` |
| 158932 | `http` |
| 158944 | `https` |
| 250579 | `1http://www.micr..PS/default.htm0@` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 161840 | `Software\Microso..nternet Settings` |
| 45699 | `0123456789ABCDEF..0000000000000015` |
| 159440 | `SOFTWARE\Microso..T\CurrentVersion` |
| 136960 | `ERROR : Unable t.. CAtlBaseModule
` |
| 160856 | `Solid;Powerful;A..Legendary;Basic;` |
| 159112 | `Floating point (..::CString class.` |
| 161160 | `Worker;Player;Dr..er;Caller;Armor;` |
| 161736 | `This is E2RU tra.. setup. Install?` |
| 159368 | `Software\ClearSystem` |
| 160588 | `\expand.ini` |
| 160744 | `Advapi32.dll` |
| 153376 | `mscoree.dll` |
| 199360 | `<?xml version='1..>
</assembly>
` |
| 161624 | `/S pid=129 subid=10 mr=0 lang=ru` |
| 143296 | `kernel32.dll` |
| 159028 | `www-authenticate` |
| 159576 | `%02X:%02X:%02X:%02X:%02X:%02X` |
| 160016 | `Content-Length` |
| 155872 | `Runtime Error!

Program: ` |
| 161276 | `userbrowser` |
| 156860 | `USER32.DLL` |
| 160824 | `checklink.info` |
| 159064 | `proxy-authenticate` |
| 161300 | `userbrowser=` |
| 143708 | `GetLogicalProcessorInformation` |
| 143680 | `GetCurrentProcessorNumber` |
| 161960 | `ProxyServer` |
| 143760 | `SetDefaultDllDirectories` |
| 160048 | `Transfer-Encoding` |
| 159316 | `iostream stream error` |
| 159412 | `InstallDate` |
| 143432 | `SetThreadStackGuarantee` |
| 143368 | `InitializeCriticalSectionEx` |
| 143500 | `WaitForThreadpoolTimerCallbacks` |
| 161576 | `download_url` |
| 143648 | `FreeLibraryWhenCallbackReturns` |
| 161720 | `Message` |
| 143620 | `FlushProcessWriteBuffers` |
| 143972 | `GetFileInformationByHandleExW` |
| 144004 | `SetFileInformationByHandleW` |
| 159736 | `keep-alive` |
| 143456 | `CreateThreadpoolTimer` |
| 156960 | `GetProcessWindowStation` |
| 160128 | `set-cookie` |
| 143872 | `GetUserDefaultLocaleName` |
| 143532 | `CloseThreadpoolTimer` |
| 143556 | `CreateThreadpoolWait` |
| 156932 | `GetUserObjectInformationW` |
| 160112 | `Trailer` |
| 159348 | `value_vm` |
| 159776 | `Location` |
| 160688 | `invalid unordered_map<K, T> key` |
| 159712 | `Connection` |
| 159872 | `Content-Length: %d
` |
| 143412 | `CreateSemaphoreExW` |
| 143480 | `SetThreadpoolTimer` |
| 143396 | `CreateEventExW` |
| 160772 | `RegOpenKeyTransactedW` |
| 143936 | `GetCurrentPackageId` |
| 143600 | `CloseThreadpoolWait` |
| 159820 | `Host: %s:%d
` |
| 159956 | `User-Agent: NSISDL/1.2
` |
| 143824 | `GetDateFormatEx` |
| 143580 | `SetThreadpoolWait` |
| 156912 | `GetLastActivePopup` |
| 143900 | `IsValidLocaleName` |
| 159640 | `string too long` |
| 141096 | `Unknown exception` |
| 143336 | `FlsFree` |
| 159552 | `twoyden.ru` |
| 143788 | `EnumSystemLocalesEx` |
| 159916 | `Content-Type: ` |
| 143324 | `FlsAlloc` |
| 160720 | `list<T> too long` |
| 159532 | `value_os` |
| 159020 | `

` |
| 156896 | `GetActiveWindow` |
| 159656 | `invalid string position` |
| 143856 | `GetTimeFormatEx` |
| 139300 | `address family not supported` |

### Constants / Known Patterns (73)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| hash | `hash::MD5` |
| exception | `exception::C++ exception` |
| exception | `exception::FuncInfo header` |
| registry | `registry::HKEY_USERS` |
| exception | `exception::CLR exception` |
| guid | `guid::IInternetSecurityManager` |
| compress | `compress::unlzx_table_three__16_lil_32` |
| runtime | `runtime::msvc_locale` |
| runtime | `runtime::msvc_date` |
| runtime | `runtime::msvc_r6002` |
| runtime | `runtime::msvc_r6008` |
| runtime | `runtime::msvc_r6009` |
| runtime | `runtime::msvc_r6010` |
| runtime | `runtime::msvc_r6016` |
| runtime | `runtime::msvc_r6017` |
| runtime | `runtime::msvc_r6018` |
| runtime | `runtime::msvc_r6019` |
| runtime | `runtime::msvc_r6024` |
| runtime | `runtime::msvc_r6025` |
| runtime | `runtime::msvc_r6026` |
| runtime | `runtime::msvc_r6027` |
| runtime | `runtime::msvc_r6028` |
| runtime | `runtime::msvc_r6031` |
| runtime | `runtime::msvc_r6032` |
| runtime | `runtime::msvc_r6033` |
| runtime | `runtime::msvc_r6034` |
| runtime | `runtime::msvc_domain_error` |
| runtime | `runtime::msvc_sing_error` |
| runtime | `runtime::msvc_tloss_error` |
| runtime | `runtime::msvc_name_unknown` |
| runtime | `runtime::msvc_rl` |
| oid | `oid::signedData` |
| oid | `oid::sha-256` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| crypto | `crypto::PKCS_DigestDecoration_SHA256__8_byt_19` |
| oid | `oid::sha256WithRSAEncryption` |
| oid | `oid::countryName` |

### Imports (674)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1024 | ??__E?isInitialized@CAtlStringMgr@ATL@@0_NA@@YAXXZ | DEBUG | 5 |
| 1423 | ATL.AtlCrtErrorCheck | DEBUG | 43 |
| 1482 | ATL.Checked.memmove_s | DEBUG | 4 |
| 1709 | ATL.CWin32Heap.~CWin32Heap | DEBUG | 2 |
| 1737 | ATL::CWin32Heap.#0 | DEBUG | 1 |
| 1758 | ATL::CWin32Heap.#1 | DEBUG | 1 |
| 1758 | ATL.CWin32Heap.Free | DEBUG | 1 |
| 1785 | ATL::CWin32Heap.#2 | DEBUG | 1 |
| 1785 | ATL.CWin32Heap.Reallocate | DEBUG | 1 |
| 1839 | ATL::CWin32Heap.#3 | DEBUG | 1 |
| 1860 | ATL::CWin32Heap.#4 | DEBUG | 1 |
| 1860 | ATL.CWin32Heap.`scalar deleting destructor' | DEBUG | 1 |
| 1891 | ATL.CStringData.Release | DEBUG | 48 |
| 1919 | ATL.CAtlStringMgr.GetInstance | DEBUG | 24 |
| 2069 | ATL::CAtlStringMgr.#0 | DEBUG | 1 |
| 2175 | ATL::CAtlStringMgr.#1 | DEBUG | 1 |
| 2175 | ATL.CAtlStringMgr.Free | DEBUG | 1 |
| 2187 | ATL::CAtlStringMgr.#2 | DEBUG | 1 |
| 2280 | ATL::CAtlStringMgr.#3 | DEBUG | 1 |
| 2280 | ATL.CAtlStringMgr.GetNilString | DEBUG | 1 |
| 2294 | ATL::CAtlStringMgr.#4 | DEBUG | 1 |
| 2297 | ATL::CAtlStringMgr.#5 | DEBUG | 1 |
| 6986 | ATL::CSocketAddr.#0 | DEBUG | 1 |
| 11134 | std.char_traits<char>.length | DEBUG | 1 |
| 11163 | std::_System_error_category.#0 | DEBUG | 4 |
| 11195 | std.error_condition.operator== | DEBUG | 1 |
| 11226 | std::_Iostream_error_category.#3 | DEBUG | 3 |
| 11226 | std.error_category.default_error_condition | DEBUG | 3 |
| 11244 | std::_System_error_category.#5 | DEBUG | 4 |
| 11244 | std.error_category.equivalent | DEBUG | 4 |
| 11277 | std::_System_error_category.#4 | DEBUG | 4 |
| 11277 | std.error_category.equivalent | DEBUG | 4 |
| 11306 | std::_Generic_error_category.#1 | DEBUG | 1 |
| 11312 | std::_Generic_error_category.#2 | DEBUG | 2 |
| 11357 | std::_Iostream_error_category.#1 | DEBUG | 1 |
| 11363 | std::_Iostream_error_category.#2 | DEBUG | 1 |
| 11363 | std._Iostream_error_category.message | DEBUG | 1 |
| 11412 | std::_System_error_category.#1 | DEBUG | 1 |
| 11418 | std::_System_error_category.#2 | DEBUG | 1 |
| 11463 | std::_System_error_category.#3 | DEBUG | 1 |
| 11463 | std._System_error_category.default_error_condition | DEBUG | 1 |
| 12501 | ATL.CSimpleStringT<wchar_t,0>.Empty | DEBUG | 3 |
| 13627 | std.basic_string<char,struct std::char_traits<char>,std::allocator<char>>.basic_string<char,struct std::char_traits<char>,std::allocator<char>> | DEBUG | 3 |
| 13792 | ATL::CAtlHttpClientT<ATL::ZEvtSyncSocket>.#0 | DEBUG | 1 |
| 13864 | ATL.CSimpleStringT<wchar_t,0>.SetLength | DEBUG | 13 |
| 14708 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>._Tidy | DEBUG | 3 |
| 15445 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>.assign | DEBUG | 1 |
| 15566 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>.erase | DEBUG | 1 |
| 15613 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>.erase | DEBUG | 1 |
| 15842 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>._Inside | DEBUG | 1 |
| 16179 | ATL.CSimpleStringT<wchar_t,0>.Reallocate | DEBUG | 1 |
| 16235 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>._Copy | DEBUG | 1 |
| 17436 | ATL::CAtlHttpClientT<ATL::ZEvtSyncSocket>.#1 | DEBUG | 1 |
| 18487 | ATL::CAtlHttpClientT<ATL::ZEvtSyncSocket>.#2 | DEBUG | 1 |
| 18710 | std._Allocate<char> | DEBUG | 2 |
| 27678 | std._Timevec.~_Timevec | DEBUG | 3 |
| 29846 | std.locale.~locale | DEBUG | 1 |
| 35133 | ATL.CRegKey.Close | DEBUG | 1 |
| 46032 | ATL.CAtlBaseModule.CAtlBaseModule | DEBUG | 1 |
| 46115 | ATL._ATL_BASE_MODULE70._ATL_BASE_MODULE70 | DEBUG | 1 |
| 46150 | ATL.CAtlBaseModule.~CAtlBaseModule | DEBUG | 1 |
| 46214 | ATL.CAtlBaseModule.GetHInstanceAt | DEBUG | 2 |
| 46520 | std::bad_alloc.#0 | DEBUG | 1 |
| 46557 | std::out_of_range.#0 | DEBUG | 3 |
| 46738 | std._Fac_node.~_Fac_node | DEBUG | 1 |
| 46759 | std._Fac_tidy_reg_t.~_Fac_tidy_reg_t | DEBUG | 1 |
| 46795 | std._Init_locks._Init_locks | DEBUG | 2 |
| 46881 | _Init_atexit.~_Init_atexit | DEBUG | 1 |
| 46936 | __Mtxinit | DEBUG | 1 |
| 46959 | _wmemset | DEBUG | 1 |
| 47021 | _wcschr | DEBUG | 2 |
| 47214 | _swprintf_s | DEBUG | 1 |
| 47242 | _memmove_s | DEBUG | 2 |
| 47318 | _LocaleUpdate._LocaleUpdate | DEBUG | 30 |
| 47454 | __wcsicmp | DEBUG | 11 |
| 47601 | __wcsicmp_l | DEBUG | 1 |
| 47820 | _wcsncpy_s | DEBUG | 21 |
| 48128 | __time32 | DEBUG | 2 |
| 49824 | _strncmp | DEBUG | 3 |
| 49973 | _wmemcpy_s | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 94180 | sub_417be4 |
| 62311 | sub_40ff67 |
| 45342 | sub_40bd1e |
| 43059 | sub_40b433 |
| 11675 | sub_40399b |
| 11813 | sub_403a25 |
| 17436 | #1 |
| 42742 | sub_40b2f6 |
| 30047 | sub_40815f |
| 31295 | sub_40863f |
| 109678 | sub_41b86e |
| 39485 | sub_40a63d |
| 30753 | sub_408421 |
| 7772 | sub_402a5c |
| 7047 | sub_402787 |
| 40648 | sub_40aac8 |
| 12257 | sub_403be1 |
| 9949 | sub_4032dd |
| 7597 | sub_4029ad |
| 110176 | sub_41ba60 |
| 130782 | 5 |
| 130833 | 6 |
| 131433 | 20 |
| 131533 | 22 |
| 131628 | 23 |
| 131723 | 24 |
| 131785 | 25 |
| 131836 | 26 |
| 131950 | 28 |
| 132389 | 35 |

### Decompilations (top 6)
#### 94180 — sub_417be4
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_417be4(int32_t **param_1)

{
    int32_t *piVar1;
    int32_t iVar2;
    code *pcVar3;
    undefined4 uVar4;
    
    piVar1 = *param_1;
    if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
       ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
        (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
        sub_41438d();
        pcVar3 = swi(3);
        uVar4 = (*pcVar3)();
        return uVar4;
    }
    return 0;
}

```
#### 62311 — sub_40ff67
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40ff67(void)

{
    int32_t *piVar1;
    int32_t iVar2;
    int32_t unaff_EBP;
    
    piVar1 = *(unaff_EBP + 8);
    *(*(unaff_EBP + 0xc) + -4) = *(unaff_EBP + -0x28);
    __FindAndUnlinkFrame(*(unaff_EBP + -0x2c));
    iVar2 = __getptd();
    *(iVar2 + 0x88) = *(unaff_EBP + -0x30);
    iVar2 = __getptd();
    *(iVar2 + 0x8c) = *(unaff_EBP + -0x34);
    if (((((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
         ((piVar1[5] == 0x19930520 || ((piVar1[5] == 0x19930521 || (piVar1[5] == 0x19930522)))))) &&
        (*(unaff_EBP + -0x38) == 0)) &&
       ((*(unaff_EBP + -0x1c) != 0 && (iVar2 = __IsExceptionObjectToBeDestroyed(piVar1[6]), iVar2 != 0)))) {
        ___DestructExceptionObject(piVar1, *(unaff_EBP + 0x10));
    }
    return;
}

```
#### 45342 — sub_40bd1e
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40bd1e(void)

{
    char *pcVar1;
    char cVar2;
    undefined4 uVar3;
    undefined4 *extraout_ECX;
    char *pcVar4;
    int32_t unaff_EBP;
    
    __EH_prolog3_GS(0x140);
    *(unaff_EBP + -0x138) = 0;
    *(unaff_EBP + -0x14c) = extraout_ECX;
    *(unaff_EBP + -4) = 1;
    uVar3 = [0x0x42d5e0];
    *(unaff_EBP + -0x124) = [0x0x42d5e0];
    *(unaff_EBP + -4) = 5;
    *extraout_ECX = uVar3;
    *(unaff_EBP + -0x138) = 1;
    sub_402f72(unaff_EBP + -0x124, 0x427920, 0x34bd3);
    sub_4036c7(0x4284c0);
    *(unaff_EBP + -4) = 6;
    sub_403680(unaff_EBP + 0xc);
    *(unaff_EBP + -4) = 7;
    sub_4036c7(0x4284c0);
    *(unaff_EBP + -4) = 8;
    sub_403680(unaff_EBP + 0x10);
    *(unaff_EBP + -4) = 9;
    sub_4036c7(0x4284c0);
    *(unaff_EBP + -4) = 10;
    sub_403680(unaff_EBP + 0x14);
    *(unaff_EBP + -4) = 0xb;
    sub_4036c7(0x4284c0);
    *(unaff_EBP + -4) = 0xc;
    sub_403680(unaff_EBP + -0x124);
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    *(unaff_EBP + -4) = 0x14;
    sub_403454();
    *(unaff_EBP + -0x120) = unaff_EBP + -0x11c;
    sub_4043a4(*(unaff_EBP + -0x128), 3);
    *(unaff_EBP + -4) = 0x15;
    pcVar4 = *(unaff_EBP + -0x120);
    *(unaff_EBP + -0x88) = 0;
    *(unaff_EBP + -0x8c) = 0;
    *(unaff_EBP + -0x9c) = 0x67452301;
    *(unaff_EBP + -0x98) = 0xefcdab89;
    pcVar1 = pcVar4 + 1;
    *(unaff_EBP + -0x94) = 0x98badcfe;
    *(unaff_EBP + -0x90) = 0x10325476;
    do {
        cVar2 = *pcVar4;
        pcVar4 = pcVar4 + 1;
    } while (cVar2 != '\0');
    sub_40bb61(*(unaff_EBP + -0x120), pcVar4 - pcVar1);
    sub_40bbfe();
    sub_402e76(unaff_EBP + -0x34);
    if (*(unaff_EBP + -0x120) != unaff_EBP + -0x11c) {
        _free(*(unaff_EBP + -0x120));
    }
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_403454();
    sub_40f652();
    return;
}

```

### Carved Files (2)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 744 |
| ? | PKCS7 | 44199 |

### Virtual Files (4)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/ru-ru | 744 | - |
| GRPICO/101/ru-ru | 20 | - |
| VER/1/ru-ru | 656 | - |
| MANIF/1/en-us | 392 | - |

### Structures (46)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 256 |
| OptionalHeader | 280 |
| Sections | 504 |
| advapi32.FT | 136192 |
| kernel32.FT | 136220 |
| rpcrt4.FT | 136628 |
| shell32.FT | 136636 |
| shlwapi.FT | 136644 |
| user32.FT | 136676 |
| ws2_32.FT | 136700 |
| ole32.FT | 136776 |
| urlmon.FT | 136792 |
| LoadConfigurationTable | 162184 |
| SEHandlers | 163584 |
| ImportTable | 169820 |
| advapi32.OFT | 170020 |
| kernel32.OFT | 170048 |
| rpcrt4.OFT | 170456 |
| shell32.OFT | 170464 |
| shlwapi.OFT | 170472 |
| user32.OFT | 170504 |
| ws2_32.OFT | 170528 |
| ole32.OFT | 170604 |
| urlmon.OFT | 170620 |
| ImportNames | 170628 |
| SecurityCookie | 178368 |
| Resources | 197632 |
| Resources.ICO | 197680 |
| Resources.GRPICO | 197704 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 31 · duration_s: 1.04

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using RC4 KSA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0028.002:Encryption Key |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| parse credit card information |  | C0019:Check String |
| receive data |  | B0030.002:C2 Communication |
| send data |  | B0030.001:C2 Communication |
| resolve DNS |  | C0011.001:DNS Communication |
| reference HTTP User-Agent string |  | C0002:HTTP Communication |
| check HTTP status code |  | C0002.014:HTTP Communication |
| initialize Winsock library |  | C0001.009:Socket Communication |

## PE Imports / Signals
import_count: 143

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 20

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@182084 len=14; $ipv6@157710 len=6 |
| contains_base64 | - | $a@138188 len=12 |
| MD5_Constants | - | $c4@45729 len=4; $c5@45739 len=4; $c6@45752 len=4; $c7@45762 len=4 |
| url | - | $url_regex@227622 len=69 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasModified_DOS_Message | - |  |
| VC8_Microsoft_Corporation | - | $a@18194 len=10 |
| Microsoft_Visual_Cpp_8 | - | $a@28 len=82; $b@25468 len=10 |
| SEH_Save | - | $a@60017 len=7 |
| SEH_Init | - | $a@3453 len=6; $b@110219 len=7 |
| anti_dbg | - | $d1@169872 len=12; $c2@170594 len=17; $c3@169284 len=17 |
| network_tcp_socket | - | $f1@170508 len=10; $c1@170442 len=9; $c2@137650 len=6; $c4@170432 len=7; $c5@170418 len=10; $c6@137232 len=7 |
| network_dns | - | $f2@170508 len=10; $c3@170466 len=11 |
| win_registry | - | $f1@170082 len=12; $c3@170050 len=11; $c6@170050 len=11 |
| win_token | - | $f1@170082 len=12; $c3@169966 len=16 |
| win_files_operation | - | $f1@169872 len=12; $c1@169670 len=9; $c2@171522 len=14; $c3@169670 len=9; $c4@169690 len=8 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@170508 len=10 |

## Generated YARA Meta
```json
{
  "rule_count": 20,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
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
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 182084,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 157710,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 138188,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "MD5_Constants",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$c4",
          "offset": 45729,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 45739,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 45752,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 45762,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 227622,
          "length": 69,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "VC8_Microsoft_Corporation",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 18194,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_8",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 28,
          "length": 82,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 25468,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 60017,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f
```

## FLOSS Strings
Total strings: 987 · per_category: `{"decoded_strings": 1, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 986}`

### FLOSS sample
- `HARDWARE\ACPI\krb.mainsetup.vbox|HARDWARE\ACPI\DSDT\VBOX__|HARDWARE\ACPI\FADT\VBOX__|HARDWARE\ACPI\RSDT\VBOX__|HARDWARE\ACPI\SSDT\VBOX__|HARDWARE\ACPI\DSDT\VirtualBox|HARDWARE\ACPI\DSDT\Parallels Work`
- ``.rdata`
- `@.data`
- `@.reloc`
- `</tq<\tm<.um`
- `,j*Yf;`
- `j*XVf9`
- `s-9>w)+>`
- `tM9>t3`
- `C 93tr`
- `<0r><9w:`
- `RRPQRh`
- `Gf94xu`
- `<p|u<3`
- `PSSSSSS`
- `Yj8Yjx`
- `SVWjA_jZ+`
- `uBjAYjZ+`
- `uHjAXf;`
- `j/_j\[f;`
- `t3h<3B`
- `t"hH3B`
- `QQSVWd`
- `PP9E u`
- `PPPPPPPP`
- `jA[jZZ+`
- `htHjlZ;`
- `HHtXHHt`
- `nt'joZ;`
- `YYjgXf9`
- `>0t<NAj0X`
- `~pjCXf`
- `v	N+D$`
- `HHtVHHt`
- `uaPPPS`
- `YY_^[]`
- `tHHt*Ht#`
- `j@j _W`
- `QQSVWh`
- `j"_f9y`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0040ee57
```asm
┌ 300: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_24h @ ebp-0x24
│       ╎   0x0040ee57      e852950000     call 0x4183ae
│       └─< 0x0040ee5c      e97ffeffff     jmp 0x40ece0
..
```
### 0x0040ada5
```asm
; CALL XREF from entry0 @ 0x40edd8(x)
┌ 1000: int main (char **argv, char **envp, int32_t envp, int32_t arg_78h, int32_t arg_28h_2, int32_t arg_28h, int32_t arg_30h, int32_t arg_48h);
│           ; arg char **argv @ esp+0x78
│           ; arg char **envp @ esp+0x7c
│           ; arg int32_t envp @ esp+0x80
│           ; arg int32_t arg_78h @ esp+0x84
│           ; arg int32_t arg_28h_2 @ esp+0x88
│           ; arg int32_t arg_28h @ esp+0x8c
│           ; arg int32_t arg_30h @ esp+0x90
│           ; arg int32_t arg_48h @ esp+0xb0
│           ; var int32_t var_10h_5 @ esp+0x20
│           ; var int32_t var_14h_7 @ esp+0x24
│           ; var int32_t var_10h_4 @ esp+0x28
│           ; var int32_t var_1ch_5 @ esp+0x2c
│           ; var int32_t var_10h_3 @ esp+0x30
│           ; var int32_t var_10h_2 @ esp+0x34
│           ; var int32_t var_1ch_4 @ esp+0x38
│           ; var int32_t var_14h_6 @ esp+0x3c
│           ; var int32_t var_10h @ esp+0x40
│           ; var int32_t var_14h_5 @ esp+0x44
│           ; var int32_t var_1ch_6 @ esp+0x48
│           ; var int32_t var_14h_4 @ esp+0x4c
│           ; var int32_t var_14h_3 @ esp+0x50
│           ; var int32_t var_34h @ esp+0x54
│           ; var int32_t var_18h_2 @ esp+0x58
│           ; var int32_t var_14h_2 @ esp+0x5c
│           ; var int32_t var_1ch_3 @ esp+0x60
│           ; var int32_t var_18h @ esp+0x64
│           ; var int32_t var_14h @ esp+0x68
│           ; var int32_t var_1ch_2 @ esp+0x6c
│           ; var int32_t var_1ch @ esp+0x70
│           0x0040ada5      55             push ebp
│           0x0040ada6      8bec           mov ebp, esp
│           0x0040ada8      83e4f8         and esp, 0xfffffff8
│           0x0040adab      b8e4350000     mov eax, 0x35e4
│           0x0040adb0      e8db940000     call 0x414290
│           0x0040adb5      a1c0c44200     mov eax, dword [0x42c4c0]   ; [0x42c4c0:4]=0xbb40e64e
│           0x0040adba      33c4           xor eax, esp
│           0x0040adbc      898424e035..   mov dword [esp + 0x35e0], eax ; [0x35e0:4]=-1
│           0x0040adc3      53             push ebx
│           0x0040adc4      56             push esi
│           0x0040adc5      33c0           xor eax, eax
│           0x0040adc7      8d4c2448       lea ecx, [arg_48h]
│           0x0040adcb      57             push edi
│           0x0040adcc      89442428       mov dword [arg_28h], eax
│           0x0040add0      e851e9ffff     call 0x409726
│           0x0040add5      33ff           xor edi, edi
│           0x0040add7      8d4c244c       lea ecx, [arg_48h]
│           0x0040addb      47             inc edi
│           0x0040addc      e8008effff     call 0x403be1
│           0x0040ade1      51             push ecx
│           0x0040ade2      8d4c2430       lea ecx, [arg_30h]
│           0x0040ade6      89442428       mov dword [arg_28h_2], eax
│           0x0040adea      e8d1daffff     call 0x4088c0
│           0x0040adef      686c7f4200     push 0x427f6c               ; 'l\x7fB'
│          
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000100 ......................................

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
  - `KERNEL32.dll!WaitForSingleObject`
  - `KERNEL32.dll!OutputDebugStringW`
  - `KERNEL32.dll!GetProcessHeap`
  - `KERNEL32.dll!WideCharToMultiByte`
  - `KERNEL32.dll!InitializeCriticalSectionAndSpinCount`
  - `USER32.dll!CharNextW`
  - `USER32.dll!MessageBoxW`
  - `USER32.dll!LoadStringW`
  - `USER32.dll!CharLowerW`
  - `USER32.dll!LoadIconW`
  - `ADVAPI32.dll!RegQueryValueExW`
  - `ADVAPI32.dll!RegCloseKey`
  - `ADVAPI32.dll!ConvertSidToStringSidW`
  - `ADVAPI32.dll!RegOpenKeyExW`
  - `ADVAPI32.dll!GetTokenInformation`
  - `SHELL32.dll!SHGetFolderPathW`
  - `ole32.dll!CoUninitialize`
  - `ole32.dll!CoInitialize`
  - `ole32.dll!CoCreateInstance`
  - `SHLWAPI.dll!StrToIntW`
  - `SHLWAPI.dll!StrDupW`
  - `SHLWAPI.dll!StrCatW`
  - `SHLWAPI.dll!PathQuoteSpacesW`
  - `SHLWAPI.dll!StrCpyW`
  - `WS2_32.dll!WSAResetEvent`
  - `WS2_32.dll!WSASetLastError`
  - `WS2_32.dll!WSAEnumNetworkEvents`
  - `WS2_32.dll!WSACreateEvent`
  - `WS2_32.dll!freeaddrinfo`
  - `RPCRT4.dll!UuidCreateSequential`
