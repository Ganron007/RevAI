## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=2f2c6d9466e8572b | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=109, sha256=2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
  Anomalies (17): BigStringHiScore (strings), CrossSectionJump (code), DelayImports×21 (imports), DownloaderApiUsage (imports), ExecutableSectionNoCode (sections), ExtraSpaceAfterResourcesDataDirectory (resources), HighXrefLoopingFunction×5 (code), HugeFunctionGapAtSectionBoundary (code), ImportByHash (imports), InvalidChecksum (integrity), InvalidSizeOfInitializedData (sections), ManyHighValueImmediates×2 (code), ManyUniqueImmediateBytes×3 (code), SectionWX (sections), SpaghettiFunction×14 (code), WeirdDebugInfoType (headers), XorInLoop×7 (code)
  High-signal anomaly locations: HighXrefLoopingFunction@36581,46146,135232; ManyHighValueImmediates@34874,37738; ManyUniqueImmediateBytes@170803,174000,187626; SpaghettiFunction@34874,36698,52894; XorInLoop@47477,143424,190322
  YARA (info, 6 total): MSVC_2013_linker, msvs2013_12_0_40629_00_update_5_rich, visual_studio_2013_update_1__12_0__also_has_this_build_number_rich, DownloadUsingWininet, ElevatePrivileges, RunShell
  Functions (15): sub_4281a3@161187, sub_42cfa3@181155, sub_40b544@43332, sub_40859c@31132, #29@65031, sub_408e4f@33359, sub_40b513@43283, sub_433395@206741, sub_401240@1600, sub_40b1bf@42431, sub_4300b0@193712, sub_40b296@42646, 9@234205, 11@234376, 12@234556
  Top high-signal imports (score≥8, 11 of 339):
    [10] kernel32.IsDebuggerPresent ×4
    [10] user32.DestroyWindow ×2
    [10] user32.DestroyMenu
    [10] user32.GetDesktopWindow
    [9] advapi32.RegCreateKeyExW ×6
    [9] advapi32.RegSetValueExW ×6
    [9] urlmon.URLDownloadToFileW ×2
    [9] advapi32.RegCreateKeyW
    [8] advapi32.AdjustTokenPrivileges ×2
    [8] advapi32.LookupPrivilegeValueW
    [8] advapi32.OpenSCManagerW
  Mid-signal imports: user32.SendMessageW, kernel32.CreateProcessW, advapi32.OpenProcessToken, kernel32.CreateThread, kernel32.QueryPerformanceCounter, kernel32.TerminateProcess, user32.SendDlgItemMessageA, kernel32.GetProcAddress, kernel32.LoadLibraryExW, kernel32.DeleteFileW, kernel32.LoadLibraryW, kernel32.LoadLibraryA, kernel32.LoadLibraryExA, kernel32.GetModuleHandleW, advapi32.RegOpenKeyExW, advapi32.RegQueryValueExW, kernel32.CreateFileW, advapi32.RegQueryValueW, kernel32.DuplicateHandle, kernel32.GetModuleHandleA, kernel32.GetModuleHandleExW
  (low-signal/noise imports: 307 omitted)
  - Constants/registry (3): registry::HKEY_LOCAL_MACHINE×6, registry::HKEY_CURRENT_USER×3, registry::HKEY_USERS×5
    Constants/apihash (1): apihash::hash(strstr)
    Constants/exception (3): exception::C++ exception, exception::FuncInfo header, exception::CLR exception
    Constants/guid (47): guid::IDispatch, guid::IAccessible, guid::IOleWindow, guid::IUnknown, guid::IWICPalette, guid::IWICBitmapSource, guid::IWICFormatConverter, guid::IWICBitmapScaler
    Constants/runtime (24): runtime::msvc_r6002, runtime::msvc_r6008, runtime::msvc_r6009, runtime::msvc_r6010, runtime::msvc_r6016, runtime::msvc_r6017, runtime::msvc_r6018, runtime::msvc_r6019
  Strings/urls (13 total): nke http://www.a..Programa ni mogo, http://www.adob..aplikacji nie mo, http://www.ado..Bu uygulama bu i, http://www.adob..ji %s nie powiod, http://www.adob..ineseSimplified=, okuyun: http://.._tr.
Ukrainian=, http://www.adob..TED_SP]
Arabic=, http://www.adob..n=Ez az alkalmaz, ii de pe http://..lp_ro.
Russian=, http://www.adob..h=%s derlemesi y, http://www.adob..seSimplified=%s, http://www.adob..ae. 
Bulgarian=, tfen http://www...reksinimlerine g
  Strings/registry (7 total): SOFTWARE\Microso..nternet Explorer, Software\Microso..olicies\Explorer, Software\Microso..olicies\Comdlg32, Software\Microso..Policies\Network, SOFTWARE\Adobe\Setup\Reader, Software\Classes\, Software\
  Strings/apis (49 total): RegisterApplicationRestart, GetLogicalProcessorInformation, GetCurrentProcessorNumber, FindFirstFileTransactedW, GetFileAttributesTransactedW, SetThreadStackGuarantee, InitializeCriticalSectionEx, WaitForThreadpoolTimerCallbacks, InitNetworkAddressControl, FreeLibraryWhenCallbackReturns, InitCommonControlsEx, FlushProcessWriteBuffers, FindActCtxSectionStringW, GetProcessWindowStation, GetFileInformationByHandleExW
  Strings (other, 231 items, omitted)
  Carved files (20): DIB@369928 (1384 bytes), DIB@371312 (2216 bytes), DIB@469540 (304 bytes), DIB@469852 (176 bytes), DIB@470076 (304 bytes), DIB@470412 (304 bytes), DIB@470748 (304 bytes), DIB@471084 (304 bytes), DIB@471420 (304 bytes), DIB@471756 (304 bytes)
  Virtual files (65): LOCALIZATION_INI/135/en-us, CUR/3/en-us, CUR/4/en-us, CUR/5/en-us, CUR/6/en-us, CUR/7/en-us, CUR/8/en-us, CUR/9/en-us, CUR/10/en-us, CUR/11/en-us
  Recovered structures (247): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, gdi32.FT, kernel32.FT, oleaut32.FT, shell32.FT, shlwapi.FT, user32.FT, version.FT, winspool.FT, ole32.FT
  Decompilations (3 top functions):
    ### 161187 (sub_4281a3, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_4281a3(int32_t **param_1)

{
    int32_t *piVar1;
    int32_t iVar2;
    code *pcVar3;
    undefined4 uVar4;
    
    piVar1 = *param_1;
    if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
       ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
        (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
        sub_42cd34();
        pcVar3 = swi(3);
        uVar4 = (*pcVar3)();
        return uVar4;
    }
    return 0;
}
```
    ### 181155 (sub_42cfa3, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_42cfa3(void)

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
    ### 43332 (sub_40b544, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40b544(void)

{
    undefined4 *puVar1;
    undefined4 uVar2;
    int32_t unaff_EBP;
    
    __EH_prolog3(4);
    if (([0x0x4559b4] != 0) && ([0x0x4559cc] == 0)) {
        func_0x0040b5dd();
        puVar1 = *(unaff_EBP + 8);
        ATL.CSimpleStringT<wchar_t,0>.operator=(puVar1);
        sub_40b2fe();
        sub_40b7c7(0x80000002, "SOFTWARE\\Adobe\\Setup\\Reader", "ErrorText", *puVar1, 1);
        uVar2 = sub_40c667();
        sub_4012cf(uVar2);
        *(unaff_EBP + -4) = 0;
        sub_40b7c7(0x80000002, "SOFTWARE\\Adobe\\Setup\\Reader", "ErrorLanguage", [0x0x45599c], 1);
        [0x0x4559b8] = 1;
        ATL.CStringData.Release();
    }
    __EH_epilog3();
    return;
}
```

## capa evidence (30 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (3): query environment variable, check OS version, get system information on Windows
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (3): get common file path, check if file exists, get file version info
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (1): delete registry key
  ATT&CK {'parts': ['Collection', 'Data from Information Repositories'], 'tactic': 'Collection', 'technique': 'Data from Information Repositories', 'subtechnique': '', 'id': 'T1213'} (1): reference SQL statements
  ATT&CK {'parts': ['Impact', 'System Shutdown/Reboot'], 'tactic': 'Impact', 'technique': 'System Shutdown/Reboot', 'subtechnique': '', 'id': 'T1529'} (1): shutdown system
  All rules (5): receive data, download URL, copy file, delete file, read .ini file

## pe_imports (318 imports, 7 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  download_file (URLDownloadToFile) [T1105]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  shell_execute (ShellExecute) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (23)
  Rules: domain, IP, contains_base64, Misc_Suspicious_Strings, url, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation, SEH_Save, SEH_Init, Check_OutputDebugStringA_iat, anti_dbg, win_hook, network_dropper, escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation

## FLOSS strings (2846 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 4 functions (asm)
  ### 0x00421c21
```c
┌ 300: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_24h @ ebp-0x24
│       ╎   0x00421c21      e81a580500     call 0x477440
│       └─< 0x00421c26      e97ffeffff     jmp 0x421aaa
..
```
  ### 0x004391d2
```c
; CALL XREF from entry0 @ 0x421ba2(x)
┌ 127: int main (char **argv, char **envp, int32_t envp, int32_t arg_14h);
│           ; arg char **argv @ ebp+0x8
│           ; arg char **envp @ ebp+0xc
│           ; arg int32_t envp @ ebp+0x10
│           ; arg int32_t arg_14h @ ebp+0x14
│           0x004391d2      55             push ebp
│           0x004391d3      8bec           mov ebp, esp
│           0x004391d5      5d             pop ebp
│       ┌─< 0x004391d6      e900000000     jmp 0x4391db
│       │   ; JUMP XREF from main @ 0x4391d6(x)
│       └─> 0x004391db      55             push ebp
│           0x004391dc      8bec           mov ebp, esp
│           0x004391de      53             push ebx
│           0x004391df      56             push esi
│           0x004391e0      57             push edi
│           0x004391e1      83cfff         or edi, 0xffffffff          ; -1
│           0x004391e4      e803a8fdff     call fcn.004139ec
│           0x004391e9      8bf0           mov esi, eax
│           0x004391eb      e87302feff     call fcn.00419463
│           0x004391f0      ff7514         push dword [arg_14h]
│           0x004391f3      ff7510         push dword [envp]
│           0x004391f6      8b5804         mov ebx, dword [eax + 4]
│           0x004391f9      ff750c         push dword [envp]
│           0x004391fc      ff7508         push dword [argv]
│           0x004391ff      e86845feff     call fcn.0041d76c
│           0x00439204      85c0           test eax, eax
│       ┌─< 0x00439206      743b           je 0x439243
│       │   0x00439208      85db           test ebx, ebx
│      ┌──< 0x0043920a      740e           je 0x43921a
│      ││   0x0043920c      8b03           mov eax, dword [ebx]
│      ││   0x0043920e      8bcb           mov ecx, ebx
│      ││   0x00439210      ff90ac000000   call dword [eax + 0xac]     ; 172
│      ││   0x00439216      85c0           test eax, eax
│     ┌───< 0x00439218      7429           je 0x439243
│     │└──> 0x0043921a      8b06           mov eax, dword [esi]
│     │ │   0x0043921c      8bce           mov ecx, esi
│     │ │   0x0043921e      ff5050         call dword [eax + 0x50]     ; 80
│     │ │   0x00439221      85c0           test eax, eax
│     │┌──< 0x00439223      7515           jne 0x43923a
│     │││   0x00439225      8b4e20         mov ecx, dword [esi + 0x20]
│     │││   0x00439228      85c9           test ecx, ecx
│    ┌────< 0x0043922a      7405           je 0x439231
│    ││││   0x0043922c      8b01      
```
  ### 0x004139ec
```c
; CALL XREF from main @ 0x4391e4(x)
┌ 9: fcn.004139ec ();
│           0x004139ec      e8a55a0000     call fcn.00419496
│           0x004139f1      8b4004         mov eax, dword [eax + 4]
└           0x004139f4      c3             ret
```
  ### 0x004235c9
```c
; CALL XREF from fcn.00419496 @ 0x40c0bf(x)
┌ 91: fcn.004235c9 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           0x004235c9      55             push ebp
│           0x004235ca      8bec           mov ebp, esp
│           0x004235cc      83ec20         sub esp, 0x20
│           0x004235cf      56             push esi
│           0x004235d0      57             push edi
│           0x004235d1      6a08           push 8                      ; 8
│           0x004235d3      59             pop ecx
│           0x004235d4      be94474400     mov esi, 0x444794
│           0x004235d9      8d7de0         lea edi, [var_20h]
│           0x004235dc      f3a5           rep movsd dword es:[edi], dword [esi]
│           0x004235de      8b750c         mov esi, dword [arg_ch]
│           0x004235e1      8b7d08         mov edi, dword [arg_8h]
│           0x004235e4      85f6           test esi, esi
│       ┌─< 0x004235e6      7413           je 0x4235fb
│       │   0x004235e8      f60610         test byte [esi], 0x10
│      ┌──< 0x004235eb      740e           je 0x4235fb
│      ││   0x004235ed      8b0f           mov ecx, dword [edi]
│      ││   0x004235ef      83e904         sub ecx, 4
│      ││   0x004235f2      51             push ecx
│      ││   0x004235f3      8b01           mov eax, dword [ecx]
│      ││   0x004235f5      8b7018         mov esi, dword [eax + 0x18]
│      ││   0x004235f8      ff5020         call dword [eax + 0x20]     ; 32
│      └└─> 0x004235fb      897df8         mov dword [var_8h], edi
│           0x004235fe      8975fc         mov dword [var_4h], esi
│           0x00423601      85f6           test esi, esi
│       ┌─< 0x00423603      740c           je 0x423611
│       │   0x00423605      f60608         test byte [esi], 8
│      ┌──< 0x00423608      7407           je 0x423611
│      ││   0x0042360a      c745f40040..   mov dword [var_ch], 0x1994000
│      └└─> 0x00423611      8d45f4         lea eax, [var_ch]
│           0x00423614      50             push eax
│           0x00423615      ff75f0         push dword [var_10h]
│           0x00423618      ff75e4         push dword [var_1ch]
│           0x0042361b      ff
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 15104/60000 chars across 9 tools -->