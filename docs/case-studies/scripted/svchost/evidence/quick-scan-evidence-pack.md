## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=28046c14ea332588 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=116, sha256=28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb
  Anomalies (7): CryptoApiUsage×24 (imports), DownloaderApiUsage×2 (imports), NoChecksum (integrity), RichMultipleLinkers (rich), SpaghettiFunction×3 (code), StackArrayInitialisationX86 (code), XorInLoop×15 (code)
  High-signal anomaly locations: CryptoApiUsage@9086,9111,9209; NoChecksum@304; SpaghettiFunction@37520,48631,56272; XorInLoop@1653,1699,2895
  YARA (signal): AccessNetworkShares, DeletesVssShadowCopy
  YARA (info, 8 total): MSVC_2002_linker, MSVC_2003_rich, ZoneAlternateStream, DownloadUsingWininet, FingerprintHardware, AutorunKey, ValuableFileExtensions, RunShell
  Functions (15): sub_40f7cd@60365, sub_404044@13380, sub_403d8a@12682, sub_40f570@59760, #3@1479, sub_406ebc@25276, sub_40d7a7@52135, sub_40d450@51280, #3@2873, sub_40ec30@57392, sub_41095c@64860, sub_401c7a@4218, sub_4039bd@11709, sub_40684c@23628, sub_407b56@28502
  Top high-signal imports (score≥8, 26 of 156):
    [10] advapi32.CryptReleaseContext ×9
    [10] advapi32.CryptCreateHash ×7
    [10] advapi32.CryptDestroyKey ×5
    [10] advapi32.CryptDestroyHash ×4
    [10] advapi32.CryptAcquireContextA ×3
    [10] advapi32.CryptGenRandom ×3
    [10] advapi32.CryptEncrypt ×2
    [10] kernel32.IsDebuggerPresent ×2
    [10] advapi32.CryptGetHashParam
    [10] advapi32.CryptHashData
    [10] advapi32.CryptImportKey
    [10] advapi32.CryptSetKeyParam
    [9] advapi32.RegSetValueExA ×4
    [9] wininet.InternetCloseHandle ×4
    [9] wininet.InternetOpenA ×2
    [9] advapi32.RegCreateKeyExA
    [9] advapi32.RegSetValueExW
    [9] wininet.HttpSendRequestA
    [9] wininet.HttpSendRequestExA
    [9] wininet.InternetConnectA
    [9] wininet.InternetCrackUrlA
    [9] wininet.InternetQueryOptionA
    [9] wininet.InternetReadFile
    [9] wininet.InternetSetOptionA
    [9] wininet.InternetWriteFile
    [8] mpr.WNetAddConnection2W
  Mid-signal imports: advapi32.OpenProcessToken, kernel32.TerminateProcess, kernel32.CreateProcessW, kernel32.CreateThread, kernel32.QueryPerformanceCounter, kernel32.GetProcAddress, kernel32.DeleteFileW, kernel32.LoadLibraryW, kernel32.CreateFileW, kernel32.GetModuleHandleW, advapi32.RegOpenKeyExA, advapi32.RegQueryValueExA, kernel32.GetModuleHandleA
  (low-signal/noise imports: 117 omitted)
  * Constants/registry (3): registry::HKEY_CURRENT_USER×3, registry::HKEY_USERS, registry::autorun
    Constants/exception (3): exception::C++ exception, exception::FuncInfo header, exception::CLR exception
    Constants/runtime (24): runtime::msvc_tloss_error, runtime::msvc_sing_error, runtime::msvc_domain_error, runtime::msvc_r6033, runtime::msvc_r6032, runtime::msvc_r6031, runtime::msvc_r6030, runtime::msvc_r6028
  Strings/ips (1 total): 91.195.12.187,19..,188.127.231.116
  Strings/registry (2 total): Software\Microso..rrentVersion\Run, Software\Locky
  Strings/suspicious (2 total): vssadmin.exe Del..dows /All /Quiet, cmd.exe /C del /Q /F "
  Strings/apis (13 total): GetVolumeInformationW, InternetReadFile, ShellExecuteW, GetProcessWindowStation, GetUserObjectInformationW, GetLogicalDrives, GetLastActivePopup, FlsFree, FlsAlloc, CorExitProcess, GetActiveWindow, FlsSetValue, FlsGetValue
  Strings (other, 282 items, omitted)
  Recovered structures (24): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, gdi32.FT, kernel32.FT, mpr.FT, netapi32.FT, shell32.FT, user32.FT, wininet.FT, ImportTable, advapi32.OFT
  Decompilations (3 top functions):
    ### 60365 (sub_40f7cd, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40f7cd(void)

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
            sub_40f570(piVar1, *(unaff_EBP + 0x10));
        }
    }
    return;
}
```
    ### 13380 (sub_404044, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_404044(void)

{
    char cVar1;
    uint16_t uVar2;
    int32_t iVar3;
    code *pcVar4;
    char *pcVar5;
    char *pcVar6;
    undefined4 uVar7;
    int32_t iVar8;
    char *pcVar9;
    int32_t unaff_EBP;
    undefined4 *puVar10;
    undefined4 uStack_2fc;
    undefined4 uStack_2f8;
    undefined4 uStack_2f4;
    int32_t iStack_2f0;
    undefined4 uStack_2ec;
    int32_t iStack_2e8;
    int32_t iStack_2e4;
    undefined *puStack_2e0;
    code *pcStack_2dc;
    int32_t iStack_2d8;
    int32_t iStack_2d4;
    int32_t iStack_2d0;
    undefined4 uStack_2cc;
    undefined4 uStack_2c8;
    char *pcStack_2c4;
    char *pcStack_2c0;
    char *pcStack_2bc;
    int32_t iStack_2b8;
    char *pcStack_2b4;
    char *pcStack_2b0;
    char *pcStack_2ac;
    undefined4 uStack_2a8;
    int32_t iStack_2a4;
    undefined4 uStack_2a0;
    undefined4 uStack_29c;
    undefined4 uStack_298;
    int32_t iStack_294;
    code *pcStack_290;
    undefined4 uStack_28c;
    
    __EH_prolog();
    *(unaff_EBP + -0x10) = &stack0xfffffd78;
    uStack_28c = 0x8003;
    pcStack_290 = 0x404065;
    (*kernel32.SetErrorMode)();
    pcStack_290 = sub_403066;
    iStack_294 = 0x404070;
    (*kernel32.SetUnhandledExceptionFilter)();
    iStack_294 = unaff_EBP + -0x28;
    pcVar9 = 0x0;
    uStack_298 = 0x80;
    *(unaff_EBP + -0x54) = 0;
    uStack_29c = 0x404084;
    uStack_29c = (*kernel32.GetCurrentProcess)();
    uStack_2a0 = 0x40408b;
    iVar3 = (*advapi32.OpenProcessToken)();
    if (iVar3 != 0) {
        uStack_2a0 = 4;
        iStack_2a4 = unaff_EBP + -0x54;
        uStack_2a8 = 0x18;
        pcStack_2ac = *(unaff_EBP + -0x28);
        pcStack_2b0 = 0x4040a0;
        (*advapi32.SetTokenInformation)();
        pcStack_2b0 = *(unaff_EBP + -0x28);
        pcStack_2b4 = 0x4040a9;
        (*kernel32.CloseHandle)();
    }
    uStack_2a0 = "Wow64DisableWow64FsRedirection";
    iStack_2a4 = "kernel32.dll";
    uStack_2a8 = 0x4040b9;
    
```
    ### 12682 (sub_403d8a, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_403d8a(void)

{
    code *pcVar1;
    char cVar2;
    undefined4 uVar3;
    int32_t iVar4;
    int32_t unaff_EBP;
    undefined *puVar5;
    undefined4 *unaff_FS_OFFSET;
    
    __EH_prolog();
    sub_4052d4(unaff_EBP + -0x88);
    *(unaff_EBP + -4) = 0;
    sub_404b68(unaff_EBP + -0x6c, unaff_EBP + -0x88, "\\_Locky_recover_instructions.txt");
    *(unaff_EBP + -4) = 1;
    sub_404b68(unaff_EBP + -0x48, unaff_EBP + -0x88, "\\_Locky_recover_instructions.bmp");
    *(unaff_EBP + -4) = 2;
    cVar2 = sub_405cde();
    if (cVar2 == '\0') {
        iVar4 = *(unaff_EBP + -0x6c);
        if (*(unaff_EBP + -0x58) < 8) {
            iVar4 = unaff_EBP + -0x6c;
        }
        sub_405d28(iVar4);
    }
    cVar2 = sub_405cde();
    if (cVar2 == '\0') {
        uVar3 = sub_405c7b(unaff_EBP + -0xa4);
        *(unaff_EBP + -4) = 3;
        sub_4039bd(unaff_EBP + -0x28, uVar3);
        *(unaff_EBP + -4) = 5;
        sub_402d33(1);
        iVar4 = *(unaff_EBP + -0x48);
        if (*(unaff_EBP + -0x34) < 8) {
            iVar4 = unaff_EBP + -0x48;
        }
        sub_405d28(iVar4);
        *(unaff_EBP + -4) = 2;
        sub_4059f4(1);
    }
    iVar4 = (*advapi32.RegOpenKeyExA)(0x80000001, "Control Panel\\Desktop", 0, 0x2001f, unaff_EBP + -0x2c);
    if (iVar4 != 0) {
        *(unaff_EBP + -0x4c) = iVar4;
        *(unaff_EBP + -0x50) = &livsx.Vtable;
        __CxxThrowException@8(unaff_EBP + -0x50, 0x414fbc);
    }
    *(unaff_EBP + -4) = 6;
    *(unaff_EBP + -0x18) = 0;
    *(unaff_EBP + -0x14) = 0xf;
    *(unaff_EBP + -0x28) = 0;
    cVar2 = sub_405579(0x413b6c);
    if (cVar2 == '\0') {
        cVar2 = sub_4057d7(1, 0);
        if (cVar2 != '\0') {
            puVar5 = *(unaff_EBP + -0x28);
            if (*(unaff_EBP + -0x14) < 0x10) {
                puVar5 = unaff_EBP + -0x28;
            }
            *puVar5 = [0x0x413b6c];
            iVar4 = *(unaff_EBP + -0x28);
            *(unaff_EBP + -0x18) = 1;
   
```

## capa evidence (50 total, showing top 15)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (4): encode data using XOR, encrypt or decrypt via WinCrypt, encrypt data using AES via x86 extensions, create new key via CryptAcquireContext
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (4): get common file path, enumerate files on Windows, enumerate files recursively, get file size
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (3): get disk information, get disk size, check OS version
  ATT&CK {'parts': ['Impact', 'Inhibit System Recovery'], 'tactic': 'Impact', 'technique': 'Inhibit System Recovery', 'subtechnique': '', 'id': 'T1490'} (1): delete volume shadow copies
  ATT&CK {'parts': ['Defense Evasion', 'Indicator Removal', 'File Deletion'], 'tactic': 'Defense Evasion', 'technique': 'Indicator Removal', 'subtechnique': 'File Deletion', 'id': 'T1070.004'} (1): delete volume shadow copies
  ATT&CK {'parts': ['Defense Evasion', 'File and Directory Permissions Modification'], 'tactic': 'Defense Evasion', 'technique': 'File and Directory Permissions Modification', 'subtechnique': '', 'id': 'T1222'} (1): set file attributes
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (1): delete registry value

## pe_imports (156 imports, 8 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  crypto_encrypt (CryptEncrypt) [T1573]
  http_client (InternetOpen) [T1071.001]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  shell_execute (ShellExecute) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (24)
  Rules: domain, IP, Locky_Ransomware_2, contains_base64, System_Tools, Dropper_Strings, Misc_Suspicious_Strings, Advapi_Hash_API, IsPE32, IsWindowsGUI, HasRichSignature, VC8_Microsoft_Corporation, Microsoft_Visual_Cpp_8, SEH_Save, SEH_Init, anti_dbg, network_http, screenshot, win_registry, win_token, win_files_operation, Str_Win32_Wininet_Library, Str_Win32_Internet_API, Str_Win32_Http_API

## FLOSS strings (554 total)
  apis (5): CorExitProcess, FlsFree, FlsSetValue, FlsGetValue, FlsAlloc
  (other strings, 75 items omitted)

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
  createprocessw @ 0x406166 (fcn.0040611c)
  heapalloc @ 0x40a663 (fcn.0040a61e)
  heapalloc @ 0x40dc46 (fcn.0040dc03)
  cryptgenrandom @ 0x402000 (fcn.00401c7a)
  cryptgenrandom @ 0x4023fd (fcn.004023c6)
  cryptgenrandom @ 0x4076af (fcn.0040769d)
  shellexecutew @ 0x403fdb (fcn.00403d8a)

<!-- evidence_assembler: used 12169/28000 chars across 7 tools -->