## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=f47060d0f7de5ee6 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=114, sha256=f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e
  Anomalies (7): CryptoApiUsage×12 (imports), DownloaderApiUsage×2 (imports), HighXrefLoopingFunction (code), ManyUniqueImmediateBytes×2 (code), NoChecksum (integrity), SpaghettiFunction×8 (code), XorInLoop×9 (code)
  High-signal anomaly locations: CryptoApiUsage@8247,9024,8210; HighXrefLoopingFunction@14512; ManyUniqueImmediateBytes@14940,20544; NoChecksum@320; SpaghettiFunction@11040,11584,19152; XorInLoop@4320,4768,11105
  YARA (info, 6 total): MSVC_2010_linker, msvs2010_rich, DownloadUsingWininet, CustomUserAgent, AutorunKey, msvc_general_x64
  Functions (15): sub_140002c50@8272, sub_140002940@7488, sub_140002230@5680, sub_140002550@6480, sub_14000bbf0@45040, sub_140001c10@4112, sub_14000b0d0@42192, sub_14000b784@43908, sub_1400012e0@1760, sub_140003300@9984, sub_140001150@1360, sub_140001840@3136, sub_140003100@9472, sub_140001fb0@5040, sub_1400027c0@7104
  Top high-signal imports (score≥8, 19 of 115):
    [10] advapi32.CryptAcquireContextW ×4
    [10] advapi32.CryptCreateHash ×2
    [10] advapi32.CryptDeriveKey ×2
    [10] advapi32.CryptDestroyHash ×2
    [10] advapi32.CryptDestroyKey ×2
    [10] advapi32.CryptHashData ×2
    [10] advapi32.CryptReleaseContext ×2
    [10] kernel32.IsDebuggerPresent ×2
    [10] advapi32.CryptDecrypt
    [10] advapi32.CryptEncrypt
    [9] advapi32.RegSetValueExA ×6
    [9] wininet.InternetCloseHandle ×4
    [9] wininet.HttpSendRequestA ×2
    [9] wininet.InternetConnectA
    [9] wininet.InternetOpenA
    [9] wininet.InternetQueryDataAvailable
    [9] wininet.InternetReadFile
    [9] wininet.InternetSetOptionA
    [9] ws2_32.WSAStartup
  Mid-signal imports: kernel32.CreateProcessA, kernel32.TerminateProcess, kernel32.QueryPerformanceCounter, kernel32.GetProcAddress, kernel32.DeleteFileA, kernel32.LoadLibraryW, kernel32.CreateFileA, kernel32.GetModuleHandleW, advapi32.RegOpenKeyExA, kernel32.CreateFileW, kernel32.GetModuleHandleA
  (low-signal/noise imports: 85 omitted)
  * Constants/registry (2): registry::HKEY_LOCAL_MACHINE×2, registry::autorun
  * Constants/crypto (1): crypto::crypto_provider
    Constants/exception (2): exception::C++ exception, exception::FuncInfo header
    Constants/runtime (23): runtime::msvc_tloss_error, runtime::msvc_sing_error, runtime::msvc_domain_error, runtime::msvc_r6033, runtime::msvc_r6032, runtime::msvc_r6031, runtime::msvc_r6030, runtime::msvc_r6028
  Strings/registry (1 total): Software\Microso..rrentVersion\Run
  Strings/apis (92 total): InternetReadFile, GetProcessWindowStation, GetUserObjectInformationW, ZwQuerySystemInformation, GetLastActivePopup, CorExitProcess, GetActiveWindow, GetSystemTimeAsFileTime, InternetQueryDataAvailable, SetUnhandledExceptionFilter, DeleteCriticalSection, QueryPerformanceCounter, FreeEnvironmentStringsW, InternetConnectA, GetEnvironmentVariableA
  Strings (other, 161 items, omitted)
  Virtual files (1): CONFIG/101/en-us
  Recovered structures (25): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, kernel32.FT, user32.FT, wininet.FT, ws2_32.FT, ImportTable, advapi32.OFT, kernel32.OFT, user32.OFT, wininet.OFT
  Decompilations (3 top functions):
    ### 8272 (sub_140002c50, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

uint32_t sub_140002c50(int64_t *param_1,int32_t *param_2)

{
    uint32_t uVar1;
    int32_t iVar2;
    int64_t iVar3;
    undefined8 uVar4;
    int64_t iVar5;
    int64_t iVar6;
    char cVar7;
    uint32_t auStackX_18 [2];
    int64_t iStackX_20;
    undefined8 in_stack_ffffffffffffffa8;
    uint64_t uVar8;
    undefined4 uVar9;
    int64_t iStack_38;
    int64_t iStack_30;
    
    uVar1 = 0;
    iStack_30 = 0;
    iStack_38 = 0;
    iStackX_20 = 0;
    uVar8 = CONCAT44(in_stack_ffffffffffffffa8 >> 0x20, 3);
    iVar3 = (*kernel32.CreateFileA)("brbconfig.tmp", 1, 1, 0, uVar8, 0x80, 0);
    if (iVar3 == -1) {
        uVar1 = (*kernel32.GetLastError)();
        if (0 < uVar1) {
            uVar1 = uVar1 & 0xffff | 0x80070000;
        }
    }
    else {
        iVar2 = (*kernel32.GetFileSize)(iVar3, 0);
        *param_2 = iVar2 + 1;
        uVar4 = (*kernel32.GetProcessHeap)();
        iVar5 = (*kernel32.HeapAlloc)(uVar4, 8, iVar2 + 1);
        uVar8 = uVar8 & 0xffffffff00000000;
        *param_1 = iVar5;
        iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, uVar8);
        uVar9 = uVar8 >> 0x20;
        if (iVar2 == 0) {
            (*kernel32.GetLastError)();
        }
        iVar2 = (*kernel32.GetLastError)();
        if ((((iVar2 == -0x7ff6ffea) &&
             (iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, CONCAT44(uVar9, 8)),
             iVar2 == 0)) || (iVar2 = (*advapi32.CryptCreateHash)(iStackX_20, 0x8003, 0, 0, &iStack_38), iVar2 == 0)) ||
           ((iVar2 = (*advapi32.CryptHashData)(iStack_38, "YnJiYm90", 8), iVar2 == 0 ||
            (iVar2 = (*advapi32.CryptDeriveKey)(iStackX_20, 0x6801, iStack_38, 0x800000, &iStack_30), iVar2 == 0)))) {
            uVar1 = (*kernel32.GetLastError)();
            if (0 < uVar1) {
                uVar1 = uVar1 & 0xffff | 0x80070000;
            }
        }
        else {
            uVar4 = (*kerne
```
    ### 7488 (sub_140002940, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_140002940(int64_t param_1,int32_t param_2)

{
    uint32_t uVar1;
    int32_t iVar2;
    int64_t iVar3;
    undefined8 uVar4;
    uint64_t uVar5;
    uint64_t uVar6;
    char cVar7;
    int64_t iVar8;
    uint32_t auStackX_18 [2];
    int64_t iStackX_20;
    undefined8 in_stack_ffffffffffffffa8;
    uint64_t uVar9;
    undefined4 uVar10;
    undefined8 uVar11;
    int64_t iStack_38;
    int64_t iStack_30;
    
    uVar6 = 0;
    uVar11 = 0;
    iStackX_20 = 0;
    iStack_30 = 0;
    iStack_38 = 0;
    uVar9 = CONCAT44(in_stack_ffffffffffffffa8 >> 0x20, 2);
    iVar3 = (*kernel32.CreateFileA)("brbconfig.tmp", 2, 1, 0, uVar9, 0x80, 0);
    uVar5 = uVar6;
    if (iVar3 == -1) {
        uVar1 = (*kernel32.GetLastError)();
        uVar6 = uVar1;
        if (0 < uVar1) {
            uVar6 = uVar1 & 0xffff | 0x80070000;
            uVar5 = 0;
        }
    }
    else {
        uVar9 = uVar9 & 0xffffffff00000000;
        iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, uVar9);
        uVar10 = uVar9 >> 0x20;
        if (iVar2 == 0) {
            (*kernel32.GetLastError)();
        }
        iVar2 = (*kernel32.GetLastError)();
        if ((((iVar2 == -0x7ff6ffea) &&
             (iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, CONCAT44(uVar10, 8)),
             iVar2 == 0)) || (iVar2 = (*advapi32.CryptCreateHash)(iStackX_20, 0x8003, 0, 0, &iStack_38), iVar2 == 0)) ||
           ((iVar2 = (*advapi32.CryptHashData)(iStack_38, "YnJiYm90", 8), iVar2 == 0 ||
            (iVar2 = (*advapi32.CryptDeriveKey)(iStackX_20, 0x6801, iStack_38, 0x800000, &iStack_30), iVar2 == 0)))) {
            uVar1 = (*kernel32.GetLastError)();
            uVar6 = uVar1;
            if (0 < uVar1) {
                uVar6 = uVar1 & 0xffff | 0x80070000;
                uVar5 = 0;
            }
        }
        else {
            uVar4 = (*kernel32.GetProcessHeap)();
          
```
    ### 5680 (sub_140002230, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_140002230(void)

{
    char cVar1;
    bool bVar2;
    int32_t iVar3;
    uint32_t uVar4;
    undefined8 uVar5;
    char *pcVar6;
    int64_t iVar7;
    int64_t *piVar8;
    uint64_t uVar9;
    uint64_t uVar10;
    int64_t iVar11;
    char *pcVar12;
    int64_t *piVar13;
    undefined auStack_288 [32];
    int64_t *piStack_268;
    uint32_t uStack_260;
    int64_t aiStack_258 [2];
    char acStack_248 [272];
    undefined uStack_138;
    undefined auStack_137 [271];
    uint64_t uStack_28;
    
    uStack_28 = [0x0x140012008] ^ auStack_288;
    uVar4 = 0x8000ffff;
    uStack_138 = 0;
    memset(auStack_137, 0, 0x103);
    acStack_248[0] = '\0';
    memset(acStack_248 + 1, 0, 0x103);
    aiStack_258[0] = 0;
    piVar8 = 0x0;
    bVar2 = false;
    uVar5 = (*kernel32.GetModuleHandleW)(0);
    iVar3 = (*kernel32.GetModuleFileNameA)(uVar5, &uStack_138, 0x104);
    if (iVar3 == 0) {
        uVar4 = (*kernel32.GetLastError)();
        if (0 < uVar4) {
            uVar4 = uVar4 & 0xffff | 0x80070000;
            bVar2 = false;
        }
    }
    else {
        pcVar6 = strrchr(&uStack_138, 0x5c);
        iVar3 = (*kernel32.GetEnvironmentVariableA)("APPDATA", acStack_248, 0x104);
        if (iVar3 != 0) {
            iVar7 = strstr(&uStack_138, acStack_248);
            uVar9 = 0xffffffffffffffff;
            pcVar12 = pcVar6;
            do {
                if (uVar9 == 0) break;
                uVar9 = uVar9 - 1;
                cVar1 = *pcVar12;
                pcVar12 = pcVar12 + 1;
            } while (cVar1 != '\0');
            uVar10 = 0xffffffffffffffff;
            pcVar12 = acStack_248;
            do {
                if (uVar10 == 0) break;
                uVar10 = uVar10 - 1;
                cVar1 = *pcVar12;
                pcVar12 = pcVar12 + 1;
            } while (cVar1 != '\0');
            uVar5 = (*kernel32.GetProcessHeap)();
            piVar8 = (*kernel32.HeapAlloc)(uVar5, 8, ~uVar9 +
```

## capa evidence (35 total, showing top 15)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (4): encode data using XOR, encrypt or decrypt via WinCrypt, encrypt data using RC4 via WinAPI, create new key via CryptAcquireContext
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (2): query environment variable, get hostname
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (2): get common file path, get file size
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (1): delete registry value
  ATT&CK {'parts': ['Persistence', 'Boot or Logon Autostart Execution', 'Registry Run Keys / Startup Folder'], 'tactic': 'Persistence', 'technique': 'Boot or Logon Autostart Execution', 'subtechnique': 'Registry Run Keys / Startup Folder', 'id': 'T1547.001'} (1): persist via Run registry key
  All rules (5): receive data, send data, write and execute a file, resolve DNS, check HTTP status code

## pe_imports (115 imports, 7 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  crypto_encrypt (CryptEncrypt) [T1573]
  http_client (InternetOpen) [T1071.001]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (17)
  Rules: domain, contains_base64, Dropper_Strings, Advapi_Hash_API, IsPE64, IsWindowsGUI, HasRichSignature, Microsoft_Visual_Cpp_80_DLL, anti_dbg, network_http, screenshot, win_registry, win_files_operation, Str_Win32_Winsock2_Library, Str_Win32_Wininet_Library, Str_Win32_Internet_API, Str_Win32_Http_API

## FLOSS strings (310 total)
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
  sink_count: 22
  heapalloc @ 0x140001039 (fcn.140001000)
  heapalloc @ 0x1400010d5 (fcn.140001000)
  heapalloc @ 0x1400017e6 (fcn.140001770)
  heapalloc @ 0x1400018c8 (fcn.140001840)
  heapalloc @ 0x140001a3c (fcn.140001840)
  heapalloc @ 0x140001ba6 (fcn.140001840)
  heapalloc @ 0x140001d0e (fcn.140001c10)
  heapalloc @ 0x140001e13 (fcn.140001c10)
  heapalloc @ 0x140001e61 (fcn.140001c10)
  heapalloc @ 0x140002057 (fcn.140001fb0)
  heapalloc @ 0x140002138 (fcn.140001fb0)
  heapalloc @ 0x14000237e (fcn.140002230)
  heapalloc @ 0x14000267d (fcn.140002550)
  heapalloc @ 0x140002ac1 (fcn.140002940)
  heapalloc @ 0x140002cf8 (fcn.140002c50)

<!-- evidence_assembler: used 12768/28000 chars across 7 tools -->