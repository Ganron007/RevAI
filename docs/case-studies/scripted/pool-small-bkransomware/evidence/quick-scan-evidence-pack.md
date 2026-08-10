## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=2f2c6d9466e8572b | packaging=v6.1 -->

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
  ⚠ Constants/registry (3): registry::HKEY_LOCAL_MACHINE×6, registry::HKEY_CURRENT_USER×3, registry::HKEY_USERS×5
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

<!-- evidence_assembler: used 9279/28000 chars across 5 tools -->