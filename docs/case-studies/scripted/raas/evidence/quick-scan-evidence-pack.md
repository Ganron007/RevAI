## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=c04836696d715c54 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=7.39, sha256=c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505
  Anomalies (10): CryptoApiUsage×3 (imports), GuiSubsystemNoWindowApi (headers), HighXrefLoopingFunction (code), HugeStringHexa (strings), NoChecksum (integrity), PossiblePackerApiDynamicImport (imports), RichUnknownTool (rich), SpaghettiFunction×5 (code), UnknownOverlayMediumToHighEntropy (entropy), XorInLoop×10 (code)
  High-signal anomaly locations: CryptoApiUsage@1171,1160,1115; GuiSubsystemNoWindowApi@316; HighXrefLoopingFunction@10058; NoChecksum@312; SpaghettiFunction@2097,26860,27920; XorInLoop@1223,1269,1341
  YARA (info, 3 total): MSVC_2013_linker, visual_studio_2013_update_1__12_0__also_has_this_build_number_rich, EnumerateProcesses
  Functions (15): sub_401d4c@4428, sub_40204f@5199, sub_402bd6@8150, sub_4010a5@1189, sub_402f70@9072, sub_402373@6003, PEBx86@7391, sub_402b77@8055, sub_4075ea@27114, sub_4082c0@30400, sub_408832@31794, sub_4051a0@17824, sub_40334a@10058, sub_403302@9986, sub_40164f@2639
  Top high-signal imports (score≥8, 11 of 83):
    [10] kernel32.IsDebuggerPresent ×3
    [10] advapi32.CryptAcquireContextW
    [10] advapi32.CryptCreateHash
    [10] advapi32.CryptDestroyHash
    [10] advapi32.CryptGetHashParam
    [10] advapi32.CryptHashData
    [10] advapi32.CryptReleaseContext
    [10] kernel32.VirtualAllocEx
    [8] kernel32.CreateToolhelp32Snapshot ×3
    [8] kernel32.VirtualProtect ×2
    [8] kernel32.VirtualAlloc
  Mid-signal imports: kernel32.CreateProcessW, kernel32.OpenProcess, kernel32.TerminateProcess, kernel32.GetProcAddress, kernel32.LoadLibraryExW, kernel32.DeleteFileW, kernel32.LoadLibraryW, kernel32.GetModuleHandleW, advapi32.RegOpenKeyExW, kernel32.CreateFileW, advapi32.RegQueryValueExW, kernel32.GetModuleHandleA, kernel32.GetModuleHandleExW
  (low-signal/noise imports: 59 omitted)
  * Constants/registry (2): registry::HKEY_LOCAL_MACHINE×8, registry::HKEY_USERS
  * Constants/crypto (1): crypto::crypto_provider×2
    Constants/hash (1): hash::xxhash
    Constants/code (1): code::PEBx86
    Constants/exception (1): exception::C++ exception
    Constants/runtime (25): runtime::msvc_date, runtime::msvc_r6002, runtime::msvc_r6008, runtime::msvc_r6009, runtime::msvc_r6010, runtime::msvc_r6016, runtime::msvc_r6017, runtime::msvc_r6018
  Strings/apis (20 total): GetProcessWindowStation, GetUserObjectInformationW, GetLastActivePopup, CorExitProcess, GetActiveWindow, RtlGetVersion, IsProcessorFeaturePresent, AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, SetUnhandledExceptionFilter, DeleteCriticalSection, FlushFileBuffers, GetCurrentProcess, GetCurrentThreadId, DeleteFileW
  Strings (other, 280 items, omitted)
  Recovered structures (20): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, kernel32.FT, shell32.FT, shlwapi.FT, user32.FT, LoadConfigurationTable, ImportTable, advapi32.OFT, kernel32.OFT, shell32.OFT
  Decompilations (3 top functions):
    ### 4428 (sub_401d4c, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_401d4c(void)

{
    code *pcVar1;
    undefined2 uVar2;
    int32_t iVar3;
    int32_t iVar4;
    undefined4 extraout_ECX;
    undefined4 extraout_ECX_00;
    undefined4 extraout_ECX_01;
    undefined4 extraout_ECX_02;
    undefined4 extraout_ECX_03;
    undefined4 extraout_ECX_04;
    undefined4 uVar5;
    undefined4 uVar6;
    int32_t iVar7;
    undefined4 **ppuStack_950;
    undefined4 uStack_94c;
    undefined *puStack_948;
    undefined4 uStack_944;
    undefined4 uStack_940;
    undefined4 *puStack_93c;
    undefined4 auStack_928 [11];
    undefined auStack_8fc [20];
    undefined auStack_8e8 [76];
    undefined auStack_89c [68];
    undefined auStack_858 [8];
    undefined auStack_850 [19];
    undefined uStack_83d;
    undefined2 auStack_83c [9];
    undefined uStack_829;
    undefined2 auStack_828 [9];
    undefined uStack_815;
    undefined2 auStack_814 [9];
    undefined auStack_801 [2049];
    
    iVar7 = 0x800;
    iVar4 = 0x800;
    do {
        iVar3 = iVar4 + -1;
        auStack_801[iVar4] = 0;
        iVar4 = iVar3;
    } while (iVar3 != 0);
    puStack_93c = 0x401d77;
    sub_40334a();
    puStack_93c = 0x401d83;
    sub_40334a();
    pcVar1 = advapi32.RegOpenKeyExW;
    puStack_93c = auStack_928;
    puStack_948 = auStack_89c;
    uVar6 = 1;
    uStack_940 = 1;
    uStack_944 = 0;
    uStack_94c = 0x80000002;
    auStack_928[0] = 0x80000002;
    ppuStack_950 = 0x401da8;
    iVar4 = (*advapi32.RegOpenKeyExW)();
    if (iVar4 == 0) {
        ppuStack_950 = 0x401db9;
        iVar4 = sub_402f09();
        uVar5 = extraout_ECX_00;
    }
    else {
        iVar4 = 0;
        uVar5 = extraout_ECX;
    }
    if ((iVar4 != 0) && (iVar4 = sub_402f70(&stack0xfffff6d4, uVar5, auStack_814), iVar4 != -1)) {
        iVar3 = 0;
        ppuStack_950 = 0x401df3;
        iVar4 = sub_403189();
        if (0 < iVar4) {
            do {
                ppuStack_950 = 0x401e04;
                uVar
```
    ### 5199 (sub_40204f, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_40204f(void)

{
    code *pcVar1;
    undefined2 uVar2;
    int32_t iVar3;
    int32_t iVar4;
    undefined4 uVar5;
    undefined4 extraout_ECX;
    undefined4 extraout_ECX_00;
    undefined4 extraout_ECX_01;
    undefined4 extraout_ECX_02;
    undefined4 extraout_ECX_03;
    undefined4 extraout_ECX_04;
    int32_t iVar6;
    int32_t iVar7;
    undefined2 *puStack_934;
    undefined4 **ppuStack_930;
    undefined4 uStack_92c;
    undefined *puStack_928;
    undefined4 uStack_924;
    undefined4 uStack_920;
    undefined4 *puStack_91c;
    undefined4 auStack_908 [3];
    undefined auStack_8fc [20];
    undefined auStack_8e8 [76];
    undefined auStack_89c [80];
    undefined2 auStack_84c [8];
    undefined auStack_83c [19];
    undefined uStack_829;
    undefined2 auStack_828 [9];
    undefined uStack_815;
    undefined2 auStack_814 [9];
    undefined auStack_801 [2049];
    
    iVar7 = 0x800;
    iVar6 = 0;
    iVar4 = 0x800;
    do {
        iVar3 = iVar4 + -1;
        auStack_801[iVar4] = 0;
        iVar4 = iVar3;
    } while (iVar3 != 0);
    puStack_91c = 0x40207b;
    sub_40334a();
    puStack_91c = 0x402087;
    sub_40334a();
    pcVar1 = advapi32.RegOpenKeyExW;
    puStack_91c = auStack_908;
    uStack_920 = 1;
    uStack_924 = 0;
    puStack_928 = auStack_89c;
    uStack_92c = 0x80000002;
    auStack_908[0] = 0x80000002;
    ppuStack_930 = 0x4020a9;
    iVar4 = (*advapi32.RegOpenKeyExW)();
    if (iVar4 == 0) {
        ppuStack_930 = 0x4020ba;
        iVar4 = sub_402f09();
        uVar5 = extraout_ECX_00;
    }
    else {
        iVar4 = 0;
        uVar5 = extraout_ECX;
    }
    if (iVar4 == 0) {
code_r0x0040214b:
        iVar4 = 0x800;
        do {
            iVar3 = iVar4 + -1;
            *(auStack_814 + iVar4 + -1) = 0;
            iVar4 = iVar3;
        } while (iVar3 != 0);
        ppuStack_930 = 0x402163;
        sub_40334a();
        ppuStack_930 = 0x40216f;
        sub_40334a
```
    ### 8150 (sub_402bd6, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_402bd6(void)

{
    int32_t iVar1;
    code *pcVar2;
    undefined4 uVar3;
    int32_t iVar4;
    undefined auStack_160 [36];
    undefined auStack_13c [36];
    undefined auStack_118 [32];
    undefined auStack_f8 [28];
    undefined auStack_dc [56];
    undefined auStack_a4 [28];
    undefined auStack_88 [52];
    undefined auStack_54 [24];
    undefined auStack_3c [24];
    undefined auStack_24 [16];
    undefined auStack_14 [12];
    undefined *puStack_8;
    
    sub_40334a();
    sub_403302();
    iVar1 = (*kernel32.LoadLibraryW)(auStack_3c);
    if ((iVar1 != 0) && (pcVar2 = (*kernel32.GetProcAddress)(iVar1, auStack_14), pcVar2 != 0x0)) {
        (*pcVar2)(1);
    }
    sub_40334a();
    sub_40334a();
    pcVar2 = kernel32.GetModuleHandleW;
    iVar1 = (*kernel32.GetModuleHandleW)(auStack_88);
    if ((iVar1 == 0) && (iVar1 = (*pcVar2)(auStack_a4), iVar1 == 0)) {
        sub_40334a();
        pcVar2 = user32.FindWindowW;
        iVar4 = 0;
        iVar1 = (*user32.FindWindowW)(auStack_24, 0);
        if (iVar1 == 0) {
            sub_40334a();
            iVar1 = (*pcVar2)(auStack_13c, 0);
            if (iVar1 == 0) {
                sub_40334a();
                iVar1 = (*pcVar2)(auStack_160, 0);
                if (iVar1 == 0) {
                    sub_40334a();
                    iVar1 = (*pcVar2)(auStack_f8, 0);
                    if (iVar1 == 0) {
                        sub_40334a();
                        iVar1 = (*pcVar2)(auStack_dc, 0);
                        if (iVar1 == 0) {
                            sub_40334a();
                            iVar1 = (*pcVar2)(auStack_54, 0);
                            if (((((iVar1 == 0) && (([0x0x7ffe02d4] & 3) == 0)) && (iVar1 = sub_4026c2(), iVar1 == 0)) &&
                                (((iVar1 = sub_4019ac(), iVar1 == 0 && (iVar1 = sub_401a61(), iVar1 == 0)) &&
                                 ((iVar1 = sub_401d4c(), iVar1 == 0 &
```

## capa evidence (27 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (3): get common file path, check if file exists, get file size
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (2): encode data using XOR, encrypt data using RC4 PRGA
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (2): query environment variable, get disk size
  ATT&CK {'parts': ['Execution', 'Command and Scripting Interpreter'], 'tactic': 'Execution', 'technique': 'Command and Scripting Interpreter', 'subtechnique': '', 'id': 'T1059'} (1): accept command line arguments
  ATT&CK {'parts': ['Discovery', 'Process Discovery'], 'tactic': 'Discovery', 'technique': 'Process Discovery', 'subtechnique': '', 'id': 'T1057'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Software Discovery'], 'tactic': 'Discovery', 'technique': 'Software Discovery', 'subtechnique': '', 'id': 'T1518'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  ATT&CK {'parts': ['Discovery', 'System Owner/User Discovery'], 'tactic': 'Discovery', 'technique': 'System Owner/User Discovery', 'subtechnique': '', 'id': 'T1033'} (1): get session user name
  ATT&CK {'parts': ['Discovery', 'Account Discovery'], 'tactic': 'Discovery', 'technique': 'Account Discovery', 'subtechnique': '', 'id': 'T1087'} (1): get session user name
  All rules (4): check for PEB NtGlobalFlag flag, execute anti-debugging instructions, hash data with CRC32, hash data via WinCrypt

## pe_imports (83 imports, 6 high-signal)
  allocate_memory (VirtualAllocEx) [T1055]
  check_debugger (IsDebuggerPresent) [T1622]
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]

## YARA matches (19)
  Rules: domain, IP, contains_base64, Advapi_Hash_API, CRC32_poly_Constant, maldoc_find_kernel32_base_method_1, IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasRichSignature, Microsoft_Visual_Cpp_v50v60_MFC, SEH__vectored, SEH_Save, SEH_Init, anti_dbg, inject_thread, win_registry, win_files_operation

## FLOSS strings (579 total)
  registry (1): SOFTWARE\VMware, Inc.\VMware Tools
  paths (2): C:\InsideTm, \\.\PhysicalDrive0
  apis (1): NtQueryInformationProcess
  (other strings, 76 items omitted)

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: present — Data Execution Prevention flag set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 5
  createprocessw @ 0x402e00 (?)
  heapalloc @ 0x4013d7 (fcn.004013c7)
  heapalloc @ 0x4063e8 (fcn.004063a5)
  heapalloc @ 0x406476 (fcn.00406437)
  virtualalloc @ 0x4011d1 (fcn.00401188)

<!-- evidence_assembler: used 12706/28000 chars across 7 tools -->