## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=0598e95ea5f28e3e | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=7.99, sha256=0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc
  Anomalies (9): BigBufferNoXrefMediumToHighEntropy×9 (entropy), DllNoRelocation (sections), ExecutableSectionNoCode (sections), HighEntropy (entropy), HugeFunctionGapAtSectionBoundary (code), SectionNameUnknown×2 (sections), SectionWX (sections), UnreferencedImports×79 (imports), XorInLoop×3 (code)
  High-signal anomaly locations: XorInLoop@7008,7021,7187
  YARA (info, 4 total): MSVC_2005_linker, DownloadUsingWininet, ProcessInjectionTargets, ElevatePrivileges
  Functions (7): sub_10002749@6985, sub_100027e5@7141, EntryPoint@6943, _Run@0@7280, sub_100027d7@7127, sub_100027cd@7117, sub_100027d4@7124
  Top high-signal imports (score≥8, 9 of 79):
    [9] wininet.InternetReadFile
    [9] advapi32.RegCreateKeyA
    [9] advapi32.RegSetValueExA
    [9] wininet.InternetCloseHandle
    [9] wininet.InternetOpenA
    [9] wininet.InternetOpenUrlA
    [8] advapi32.AdjustTokenPrivileges
    [8] advapi32.LookupPrivilegeValueW
    [8] kernel32.VirtualAlloc
  Mid-signal imports: advapi32.OpenProcessToken, kernel32.CreateProcessW, kernel32.CreateThread, user32.SendMessageW, advapi32.RegOpenKeyA, advapi32.RegQueryValueExA, kernel32.CreateFileA, kernel32.CreateFileW
  (low-signal/noise imports: 62 omitted)
    Constants/guid (2): guid::IShellLinkW, guid::IPersistFile
  Strings/apis (49 total): InternetReadFile, DisableThreadLibraryCalls, InitializeCriticalSection, DeleteCriticalSection, GetFileAttributesA, CoCreateInstance, InternetOpenUrlA, InternetCloseHandle, InternetOpenA, GetCurrentProcess, InitiateSystemShutdownW, GetVolumeInformationA, OpenProcessToken, CreateDialogParamA, CreateThread
  Strings (other, 251 items, omitted)
  Recovered structures (27): MZ, PE, OptionalHeader, Sections, advapi32.FT, kernel32.FT, shell32.FT, shlwapi.FT, user32.FT, wininet.FT, ntdll.FT, ole32.FT, ImportTable, advapi32.OFT, kernel32.OFT
  Decompilations (3 top functions):
    ### 6985 (sub_10002749, score=?)
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
    ### 7141 (sub_100027e5, score=?)
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
    ### 6943 (EntryPoint, score=?)
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

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  ATT&CK {'parts': ['Defense Evasion', 'Virtualization/Sandbox Evasion', 'System Checks'], 'tactic': 'Defense Evasion', 'technique': 'Virtualization/Sandbox Evasion', 'subtechnique': 'System Checks', 'id': 'T1497.001'} (1): reference anti-VM strings targeting Xen
  All rules (1): contain loop

## pe_imports (79 imports, 4 high-signal)
  http_client (InternetOpen) [T1071.001]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (16)
  Rules: domain, IP, contains_base64, Browsers, IsPE32, IsDLL, IsWindowsGUI, IsPacked, Microsoft_Visual_Basic_v50, escalate_priv, win_mutex, win_registry, win_token, win_files_operation, Str_Win32_Wininet_Library, Str_Win32_Internet_API

## FLOSS strings (695 total)
  registry (1): Software\
  apis (16): InternetOpenUrlA, InternetReadFile, InternetOpenA, InternetCloseHandle, GetComputerNameA, CreateMutexW, WaitForSingleObject, GetTickCount, VirtualFree, InitializeCriticalSection, GetVolumeInformationA, GetTempPathW
  (other strings, 63 items omitted)

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: missing — Data Execution Prevention flag not set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: missing — NO_SEH flag set — no SEH handlers claimed
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 0

<!-- evidence_assembler: used 5655/28000 chars across 7 tools -->