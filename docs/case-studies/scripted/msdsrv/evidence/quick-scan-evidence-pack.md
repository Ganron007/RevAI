## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=ef2d290a0b2ca89c | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=112, sha256=ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98
  Anomalies (8): DownloaderApiUsage×6 (imports), HighXrefLoopingFunction×3 (code), InvalidChecksum (integrity), ManyHighValueImmediates (code), ManyUniqueImmediateBytes×2 (code), SpaghettiFunction×14 (code), StackArrayInitialisationX86 (code), XorInLoop×15 (code)
  High-signal anomaly locations: HighXrefLoopingFunction@14784,19476,78064; ManyHighValueImmediates@113106; ManyUniqueImmediateBytes@106530,110114; SpaghettiFunction@6352,14576,23451; XorInLoop@71099,71149,71170
  YARA (info, 6 total): MSVC_2008_linker, MSVC_2005_rich, MSVC_2008_rich, DownloadUsingWininet, FingerprintHardware, FingerprintEnvironment
  Functions (15): sub_41c5d2@113106, sub_41d3dc@116700, sub_4041b0@13744, #29@46572, sub_404000@13312, sub_41d17a@116090, sub_41a454@104532, 58@158459, 61@158713, 64@158995, 5@156233, 6@156284, 20@156865, 29@157278, 31@157375
  Top high-signal imports (score≥8, 14 of 264):
    [10] kernel32.IsDebuggerPresent ×2
    [10] user32.DestroyMenu
    [10] user32.DestroyWindow
    [9] wininet.InternetReadFile ×5
    [9] wininet.InternetCloseHandle ×3
    [9] wininet.InternetWriteFile ×3
    [9] wininet.InternetSetStatusCallback ×2
    [9] wininet.HttpSendRequestExA
    [9] wininet.InternetConnectA
    [9] wininet.InternetGetLastResponseInfoA
    [9] wininet.InternetOpenA
    [9] wininet.InternetQueryDataAvailable
    [9] wininet.InternetSetFilePointer
    [8] kernel32.VirtualAlloc ×2
  Mid-signal imports: user32.SendMessageA, kernel32.TerminateProcess, kernel32.QueryPerformanceCounter, kernel32.GetProcAddress, kernel32.LoadLibraryA, kernel32.DeleteFileA, kernel32.GetModuleHandleW, kernel32.GetModuleHandleA, kernel32.CreateFileA, kernel32.DuplicateHandle
  (low-signal/noise imports: 240 omitted)
  * Constants/registry (2): registry::HKEY_USERS×6, registry::HKEY_LOCAL_MACHINE
    Constants/exception (3): exception::C++ exception, exception::FuncInfo header, exception::CLR exception
    Constants/guid (8): guid::IShellLinkA, guid::IPersistFile, guid::IAccessible, guid::IDispatch, guid::IOleWindow, guid::IUnknown, guid::IFileDialogEvents, guid::IFileDialogControlEvents
    Constants/runtime (16): runtime::msvc_r6034, runtime::msvc_r6033, runtime::msvc_r6031, runtime::msvc_r6027, runtime::msvc_r6026, runtime::msvc_r6025, runtime::msvc_r6024, runtime::msvc_r6019
  Strings/ips (2 total): 13.9.6.11, 14.8.1.6
  Strings/apis (22 total): GetVolumeInformationA, InternetReadFile, InitCommonControls, GetComputerNameA, InitCommonControlsEx, GetProcessWindowStation, MonitorFromWindow, GetUserNameA, GetUserObjectInformationA, GetSystemMetrics, HeapQueryInformation, GetVersionExA, GetLastActivePopup, GetMonitorInfoA, FlsFree
  Strings (other, 276 items, omitted)
  Carved files (7): DIB@230992 (3752 bytes), DIB@234744 (2216 bytes), DIB@236960 (1384 bytes), DIB@238344 (67624 bytes), DIB@305968 (9640 bytes), DIB@315608 (4264 bytes), DIB@319872 (1128 bytes)
  Virtual files (10): ICO/1/id-id, ICO/2/id-id, ICO/3/id-id, ICO/4/id-id, ICO/5/id-id, ICO/6/id-id, ICO/7/id-id, GRPICO/131/id-id, VER/1/id-id, MANIF/1/en-us
  Recovered structures (70): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, comdlg32.FT, gdi32.FT, kernel32.FT, oleacc.FT, oleaut32.FT, shell32.FT, shlwapi.FT, user32.FT, wininet.FT
  Decompilations (3 top functions):
    ### 113106 (sub_41c5d2, score=?)
```c
/* WARNING: This function may have set the stack pointer */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 __fastcall sub_41c5d2(int32_t param_1,char param_2)

{
    int32_t *piVar1;
    int32_t iVar2;
    int32_t unaff_EBP;
    char *unaff_EDI;
    
    *(param_1 + -0x43) = *(param_1 + -0x43) + param_1 + '\x01';
    *(unaff_EBP + -0x5effbe44) = *(unaff_EBP + -0x5effbe44) + param_2;
    *unaff_EDI = *unaff_EDI + param_2;
    piVar1 = *0xbce70045;
    bce7003d = unaff_EBP;
    if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
       ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
        (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
        [0x0xbce70039] = 0x41c62e;
        terminate();
    }
    return 0;
}
```
    ### 116700 (sub_41d3dc, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_41d3dc(void)

{
    int32_t *piVar1;
    int32_t iVar2;
    int32_t unaff_EBP;
    
    piVar1 = *(unaff_EBP + 8);
    *(*(unaff_EBP + 0xc) + -4) = *(unaff_EBP + -0x24);
    __FindAndUnlinkFrame(*(unaff_EBP + -0x28));
    iVar2 = __getptd();
    *(iVar2 + 0x88) = *(unaff_EBP + -0x2c);
    iVar2 = __getptd();
    *(iVar2 + 0x8c) = *(unaff_EBP + -0x30);
    if ((((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
        ((iVar2 = piVar1[5], iVar2 == 0x19930520 || ((iVar2 == 0x19930521 || (iVar2 == 0x19930522)))))) &&
       ((*(unaff_EBP + -0x34) == 0 && (*(unaff_EBP + -0x1c) != 0)))) {
        iVar2 = __IsExceptionObjectToBeDestroyed(piVar1[6]);
        if (iVar2 != 0) {
            sub_41d17a(piVar1, *(unaff_EBP + 0x10));
        }
    }
    return;
}
```
    ### 13744 (sub_4041b0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_4041b0(void)

{
    int32_t iVar1;
    int32_t *unaff_EDI;
    undefined4 uStack_258;
    int32_t **ppiStack_254;
    int32_t *piStack_250;
    undefined4 *puStack_24c;
    int32_t *piStack_248;
    int32_t **ppiStack_244;
    int32_t *piStack_240;
    undefined4 *puStack_23c;
    int32_t *piStack_238;
    int32_t *piStack_234;
    undefined4 uStack_230;
    int32_t *piStack_22c;
    undefined4 uStack_228;
    undefined *puStack_224;
    undefined *puStack_220;
    undefined4 uStack_21c;
    undefined auStack_214 [528];
    uint32_t uStack_4;
    
    uStack_4 = [0x0x432be0#SecurityCookie] ^ auStack_214;
    uStack_21c = 0;
    puStack_220 = 0x4041cf;
    (*ole32.CoInitialize)();
    puStack_220 = &stack0xfffffde8;
    puStack_224 = &IShellLinkA;
    uStack_228 = 1;
    piStack_22c = 0x0;
    uStack_230 = 0x429530;
    piStack_234 = 0x4041e8;
    iVar1 = (*ole32.CoCreateInstance)();
    if (-1 < iVar1) {
        piStack_238 = piStack_22c;
        puStack_23c = 0x4041f9;
        (**(*piStack_22c + 0x50))();
        puStack_23c = 0x42c982;
        piStack_240 = piStack_234;
        ppiStack_244 = 0x40420a;
        (**(*piStack_234 + 0x1c))();
        ppiStack_244 = &piStack_238;
        piStack_248 = &IPersistFile;
        puStack_24c = puStack_23c;
        piStack_250 = 0x40421f;
        iVar1 = (***puStack_23c)();
        if (-1 < iVar1) {
            piStack_250 = 0x104;
            ppiStack_254 = &piStack_240;
            uStack_258 = 0xffffffff;
            (*kernel32.MultiByteToWideChar)(0, 0);
            (**(*unaff_EDI + 0x18))(unaff_EDI, &uStack_258);
            (**([0x0x1] + 8))(1);
        }
        piStack_250 = piStack_248;
        ppiStack_254 = 0x404269;
        (**(*piStack_248 + 8))();
    }
    uStack_230 = 0x40427a;
    sub_411faa();
    return;
}
```

## capa evidence (22 total, showing top 15)
  ATT&CK {'parts': ['Collection', 'Input Capture', 'Keylogging'], 'tactic': 'Collection', 'technique': 'Input Capture', 'subtechnique': 'Keylogging', 'id': 'T1056.001'} (2): log keystrokes via application hook, log keystrokes via polling
  ATT&CK {'parts': ['Collection', 'Clipboard Data'], 'tactic': 'Collection', 'technique': 'Clipboard Data', 'subtechnique': '', 'id': 'T1115'} (2): open clipboard, read clipboard data
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using Base64
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (1): get common file path
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (1): get hostname
  ATT&CK {'parts': ['Discovery', 'System Owner/User Discovery'], 'tactic': 'Discovery', 'technique': 'System Owner/User Discovery', 'subtechnique': '', 'id': 'T1033'} (1): get session user name
  ATT&CK {'parts': ['Discovery', 'Account Discovery'], 'tactic': 'Discovery', 'technique': 'Account Discovery', 'subtechnique': '', 'id': 'T1087'} (1): get session user name
  All rules (7): connect to HTTP server, create HTTP request, create directory, delete file, move file, get graphical window text, terminate process

## pe_imports (264 imports, 5 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  http_client (InternetOpen) [T1071.001]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (19)
  Rules: domain, IP, contains_base64, IsPE32, IsWindowsGUI, HasRichSignature, VC8_Microsoft_Corporation, Microsoft_Visual_Cpp_8, SEH_Save, SEH_Init, anti_dbg, win_hook, network_http, screenshot, keylogger, win_files_operation, Str_Win32_Wininet_Library, Str_Win32_Internet_API, Str_Win32_Http_API

## FLOSS strings (1166 total)
  (other strings, 80 items omitted)

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: present — Data Execution Prevention flag set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 7
  heapalloc @ 0x412c21 (fcn.00412c0d)
  heapalloc @ 0x413aee (fcn.00413a11)
  heapalloc @ 0x4184e7 (fcn.0041848a)
  heapalloc @ 0x4212c7 (fcn.00421209)
  heapalloc @ 0x423e56 (fcn.00423de6)
  virtualalloc @ 0x418501 (fcn.0041848a)
  virtualalloc @ 0x41858e (fcn.0041853a)

<!-- evidence_assembler: used 10090/28000 chars across 7 tools -->