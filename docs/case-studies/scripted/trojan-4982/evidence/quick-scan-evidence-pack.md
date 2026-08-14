## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=38b1bbc48c35a5de | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=6.82, sha256=38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73
  Anomalies (7): BigStringHiScore (strings), DynamicString (strings), InvalidChecksum (integrity), ManyUniqueImmediateBytes×5 (code), SequentialFunction (code), SpaghettiFunction×8 (code), XorInLoop×16 (code)
  High-signal anomaly locations: DynamicString@45699; ManyUniqueImmediateBytes@36517,43059,70759; SequentialFunction@43059; SpaghettiFunction@47820,48208,51620; XorInLoop@11571,30154,30274
  YARA (signal): ChangeBrowserPreference
  YARA (info, 1 total): MSVC_2013_linker
  Functions (15): sub_417be4@94180, sub_40ff67@62311, sub_40bd1e@45342, sub_40b433@43059, sub_40399b@11675, sub_403a25@11813, #1@17436, sub_40b2f6@42742, sub_40815f@30047, sub_40863f@31295, sub_41b86e@109678, sub_40a63d@39485, sub_408421@30753, sub_402a5c@7772, sub_402787@7047
  Top high-signal imports (score≥8, 6 of 143):
    [10] kernel32.IsDebuggerPresent ×4
    [10] kernel32.HeapDestroy
    [9] ws2_32.WSAStartup
    [8] kernel32.VirtualAlloc
    [8] kernel32.VirtualProtect
    [8] ws2_32.WSAConnect
  Mid-signal imports: advapi32.OpenProcessToken, kernel32.CreateProcessW, kernel32.QueryPerformanceCounter, kernel32.TerminateProcess, ws2_32.WSARecv, ws2_32.WSASend, kernel32.GetProcAddress, kernel32.DeleteFileW, kernel32.LoadLibraryExW, advapi32.RegQueryValueExW, kernel32.CreateFileW, advapi32.RegOpenKeyExW, kernel32.GetModuleHandleW, kernel32.GetModuleHandleExW
  (low-signal/noise imports: 123 omitted)
  * Constants/registry (3): registry::HKEY_CURRENT_USER×3, registry::HKEY_LOCAL_MACHINE×2, registry::HKEY_USERS×5
  * Constants/crypto (1): crypto::PKCS_DigestDecoration_SHA256__8_byt_19×2
    Constants/hash (1): hash::MD5
    Constants/exception (3): exception::C++ exception, exception::FuncInfo header, exception::CLR exception
    Constants/guid (1): guid::IInternetSecurityManager
    Constants/compress (1): compress::unlzx_table_three__16_lil_32
    Constants/runtime (24): runtime::msvc_locale, runtime::msvc_date, runtime::msvc_r6002, runtime::msvc_r6008, runtime::msvc_r6009, runtime::msvc_r6010, runtime::msvc_r6016, runtime::msvc_r6017
    Constants/oid (39): oid::signedData, oid::sha-256, oid::spcIndirectDataContext, oid::spcPEImageData, oid::sha256WithRSAEncryption, oid::countryName, oid::stateOrProvinceName, oid::localityName
  Strings/urls (9 total): Ehttp://www.micr.._2011-10-19.crt0, Chttp://www.micr..2011-10-19.crl0a, Ehttp://crl.micr..2010-06-23.crl0Z, Ehttp://crl.micr..2010-07-01.crl0Z, >http://www.micr..2010-06-23.crt0, >http://www.micr.._2010-06-23.crt0, >http://www.micr.._2010-07-01.crt0, 1http://www.micr..PS/default.htm0@
  Strings/ips (2 total): 1.1.0.1
  Strings/registry (3 total): Software\Microso..nternet Settings, SOFTWARE\Microso..T\CurrentVersion, Software\ClearSystem
  Strings/apis (34 total): GetLogicalProcessorInformation, GetCurrentProcessorNumber, SetDefaultDllDirectories, SetThreadStackGuarantee, InitializeCriticalSectionEx, WaitForThreadpoolTimerCallbacks, FreeLibraryWhenCallbackReturns, FlushProcessWriteBuffers, GetFileInformationByHandleExW, SetFileInformationByHandleW, CreateThreadpoolTimer, GetProcessWindowStation, GetUserDefaultLocaleName, CloseThreadpoolTimer, CreateThreadpoolWait
  Strings (other, 252 items, omitted)
  Carved files (2): DIB@197936 (744 bytes), PKCS7@209928 (44199 bytes)
  Virtual files (4): ICO/1/ru-ru, GRPICO/101/ru-ru, VER/1/ru-ru, MANIF/1/en-us
  Recovered structures (46): MZ, PE, OptionalHeader, Sections, advapi32.FT, kernel32.FT, rpcrt4.FT, shell32.FT, shlwapi.FT, user32.FT, ws2_32.FT, ole32.FT, urlmon.FT, LoadConfigurationTable, SEHandlers
  Decompilations (3 top functions):
    ### 94180 (sub_417be4, score=?)
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
    ### 62311 (sub_40ff67, score=?)
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
    ### 45342 (sub_40bd1e, score=?)
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

## capa evidence (31 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (3): get common file path, check if file exists, get file size
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (2): encode data using XOR, encrypt data using RC4 KSA
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Defense Evasion', 'File and Directory Permissions Modification'], 'tactic': 'Defense Evasion', 'technique': 'File and Directory Permissions Modification', 'subtechnique': '', 'id': 'T1222'} (1): set file attributes
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  All rules (7): parse credit card information, receive data, send data, resolve DNS, reference HTTP User-Agent string, check HTTP status code, initialize Winsock library

## pe_imports (143 imports, 6 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (20)
  Rules: domain, IP, contains_base64, MD5_Constants, url, IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message, VC8_Microsoft_Corporation, Microsoft_Visual_Cpp_8, SEH_Save, SEH_Init, anti_dbg, network_tcp_socket, network_dns, win_registry, win_token, win_files_operation, Str_Win32_Winsock2_Library

## FLOSS strings (987 total)
  (other strings, 80 items omitted)

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: present — claim only: DYNAMIC_BASE set but no .reloc section — loads at preferred base
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: present — Data Execution Prevention flag set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 7
  createprocessw @ 0x40a8f0 (fcn.0040a63d)
  heapalloc @ 0x4012d4 (method.ATL::CWin32Heap.virtual_0)
  heapalloc @ 0x404834 (fcn.004047ee)
  heapalloc @ 0x40d348 (fcn.0040d305)
  heapalloc @ 0x413c60 (fcn.00413c21)
  heapalloc @ 0x41c389 (fcn.0041c319)
  virtualalloc @ 0x40d47d (fcn.0040d3e7)

<!-- evidence_assembler: used 10191/28000 chars across 7 tools -->