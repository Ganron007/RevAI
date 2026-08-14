## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=cd78cf4af8e37b4a | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=104, sha256=cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a
  Anomalies (5): DownloaderApiUsage (imports), GuiSubsystemNoWindowApi (headers), NoChecksum (integrity), SpaghettiFunction×6 (code), XorInLoop×6 (code)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@316; NoChecksum@312; SpaghettiFunction@1680,2112,5516; XorInLoop@1171,1202,1712
  YARA (info, 4 total): MSVC_2010_linker, msvs2010_rich, DownloadUsingWininet, msvc_general_x64
  Functions (15): sub_140004040@13376, sub_140001000@1024, sub_140003bd8@12248, sub_140001938@3384, sub_14000623d@22077, sub_140002c08@8200, sub_14000331c@10012, jmp_kernel32.RtlVirtualUnwind@21934, jmp_kernel32.RtlLookupFunctionEntry@21940, jmp_kernel32.RtlUnwindEx@21946, sub_140002b98@8088, sub_140002bd0@8144, sub_140004010@13328, sub_1400061de@21982, sub_140006202@22018
  Top high-signal imports (score≥8, 2 of 60):
    [10] kernel32.IsDebuggerPresent ×3
    [9] urlmon.URLDownloadToFileA ×2
  Mid-signal imports: kernel32.CreateProcessA, kernel32.TerminateProcess, kernel32.QueryPerformanceCounter, kernel32.GetProcAddress, kernel32.LoadLibraryW, kernel32.GetModuleHandleW
  (low-signal/noise imports: 52 omitted)
    Constants/exception (2): exception::C++ exception, exception::FuncInfo header
    Constants/runtime (23): runtime::msvc_tloss_error, runtime::msvc_sing_error, runtime::msvc_domain_error, runtime::msvc_r6033, runtime::msvc_r6032, runtime::msvc_r6031, runtime::msvc_r6030, runtime::msvc_r6028
  Strings/apis (45 total): GetProcessWindowStation, GetUserObjectInformationW, GetLastActivePopup, GetActiveWindow, CorExitProcess, GetSystemTimeAsFileTime, SetUnhandledExceptionFilter, DeleteCriticalSection, QueryPerformanceCounter, FreeEnvironmentStringsW, GetEnvironmentStringsW, GetCurrentProcess, GetCurrentThreadId, GetCurrentProcessId, HeapSetInformation
  Strings (other, 113 items, omitted)
  Recovered structures (13): MZ, RichHeader, PE, OptionalHeader, Sections, kernel32.FT, urlmon.FT, ImportTable, kernel32.OFT, urlmon.OFT, ImportNames, ExceptionTable, Relocations
  Decompilations (3 top functions):
    ### 13376 (sub_140004040, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_140004040(void)

{
    return;
}
```
    ### 1024 (sub_140001000, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_140001000(void)

{
    char cVar1;
    int32_t iVar2;
    uint32_t uVar3;
    int64_t iVar4;
    int64_t iVar5;
    char *pcVar6;
    undefined auStack_718 [32];
    uint64_t uStack_6f8;
    undefined4 uStack_6f0;
    undefined8 uStack_6e8;
    undefined8 uStack_6e0;
    undefined4 *puStack_6d8;
    undefined8 *puStack_6d0;
    undefined8 uStack_6c8;
    undefined8 uStack_6c0;
    undefined8 uStack_6b8;
    undefined4 auStack_6a8 [2];
    undefined auStack_6a0 [104];
    undefined uStack_638;
    undefined auStack_637 [271];
    undefined uStack_528;
    undefined auStack_527 [271];
    undefined uStack_418;
    undefined auStack_417 [1023];
    uint64_t uStack_18;
    
    uStack_18 = [0x0x14000a008] ^ auStack_718;
    iVar2 = (*kernel32.IsDebuggerPresent)();
    if (iVar2 == 0) {
        uStack_528 = 0;
        memset(auStack_527, 0, 0x103);
        uStack_638 = 0;
        memset(auStack_637, 0, 0x103);
        uStack_418 = 0;
        memset(auStack_417, 0, 0x3ff);
        iVar5 = 0;
        iVar4 = iVar5;
        do {
            *(iVar4 + 0x14000aec0) = *(iVar4 + 0x14000aec0) ^ 0x83;
            *(iVar4 + 0x14000aec1) = *(iVar4 + 0x14000aec1) ^ 0x83;
            iVar4 = iVar4 + 2;
        } while (iVar4 < 0x80);
        do {
            *(iVar5 + 0x14000af40) = *(iVar5 + 0x14000af40) ^ 0x83;
            *(iVar5 + 0x14000af41) = *(iVar5 + 0x14000af41) ^ 0x83;
            iVar5 = iVar5 + 2;
        } while (iVar5 < 0x80);
        uVar3 = (*kernel32.GetTempPathA)(0x104, &uStack_528);
        if (((uVar3 != 0) && (uVar3 < 0x104)) &&
           (iVar2 = (*kernel32.GetTempFileNameA)(&uStack_528, 0x140008aa0, 0, &uStack_638), iVar2 != 0)) {
            strncpy(&uStack_418, 0x14000aec0, 0x3ff);
            iVar4 = -1;
            pcVar6 = 0x14000af40;
            do {
                if (iVar4 == 0) break;
                iVar4 = iVar4 + -1;
                cVar1 = *pcVar6;
                pcVar6 = pcVar6
```
    ### 12248 (sub_140003bd8, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_140003bd8(undefined8 param_1,undefined8 param_2,uint32_t param_3)

{
    int32_t iVar1;
    int64_t iVar2;
    int64_t iVar3;
    int64_t iVar4;
    undefined8 uVar5;
    code *pcVar6;
    code *pcVar7;
    int64_t iVar8;
    undefined auStack_88 [32];
    undefined *puStack_68;
    undefined auStack_58 [8];
    undefined auStack_50 [8];
    uint8_t uStack_48;
    uint64_t uStack_40;
    
    uStack_40 = [0x0x14000a008] ^ auStack_88;
    iVar2 = sub_140002c08();
    iVar8 = 0;
    if ([0x0x14000bf78] == 0) {
        iVar3 = (*kernel32.LoadLibraryW)("USER32.DLL");
        if ((iVar3 == 0) || (iVar4 = (*kernel32.GetProcAddress)(iVar3, "MessageBoxW"), iVar4 == 0))
        goto code_r0x000140003dc4;
        000000014000bf78 = (*kernel32.EncodePointer)(iVar4);
        uVar5 = (*kernel32.GetProcAddress)(iVar3, "GetActiveWindow");
        000000014000bf80 = (*kernel32.EncodePointer)(uVar5);
        uVar5 = (*kernel32.GetProcAddress)(iVar3, "GetLastActivePopup");
        000000014000bf88 = (*kernel32.EncodePointer)(uVar5);
        uVar5 = (*kernel32.GetProcAddress)(iVar3, "GetUserObjectInformationW");
        000000014000bf98 = (*kernel32.EncodePointer)(uVar5);
        if (000000014000bf98 != 0) {
            uVar5 = (*kernel32.GetProcAddress)(iVar3, "GetProcessWindowStation");
            000000014000bf90 = (*kernel32.EncodePointer)(uVar5);
        }
    }
    if (([0x0x14000bf90] == iVar2) || ([0x0x14000bf98] == iVar2)) {
code_r0x000140003d60:
        if ((([0x0x14000bf80] != iVar2) &&
            (((pcVar6 = (*kernel32.DecodePointer)(), pcVar6 != 0x0 && (iVar8 = (*pcVar6)(), iVar8 != 0)) &&
             ([0x0x14000bf88] != iVar2)))) && (pcVar6 = (*kernel32.DecodePointer)(), pcVar6 != 0x0)) {
            iVar8 = (*pcVar6)(iVar8);
        }
    }
    else {
        pcVar6 = (*kernel32.DecodePointer)([0x0x14000bf90]);
        pcVar7 = (*kernel32.DecodePointer)([0x0x14000bf98]);
        if ((pcVar6 == 0x0) || 
```

## capa evidence (8 total, showing top 8)
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (2): link function at runtime on Windows, link many functions at runtime
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (1): get common file path
  All rules (4): receive data, download URL, create process on Windows, terminate process

## pe_imports (60 imports, 5 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  download_file (URLDownloadToFile) [T1105]
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (8)
  Rules: domain, contains_base64, IsPE64, IsWindowsGUI, HasRichSignature, Microsoft_Visual_Cpp_80_DLL, anti_dbg, network_dropper

## FLOSS strings (173 total)
  apis (23): CorExitProcess, GetProcessWindowStation, GetUserObjectInformationW, GetLastActivePopup, GetActiveWindow, CreateProcessA, GetTempFileNameA, GetTempPathA, GetCommandLineA, GetStartupInfoW, TerminateProcess, GetCurrentProcess
  (other strings, 57 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x140001740
```c
┌ 401: entry0 ();
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   ; var int64_t var_30h @ rsp+0x30
│       ╎   ; var int64_t var_6ch @ rsp+0x6c
│       ╎   ; var int64_t var_70h @ rsp+0x70
│       ╎   ; var int64_t var_b0h @ rsp+0xb0
│       ╎   ; var int64_t var_10h @ rsp+0xb8
│       ╎   0x140001740      4883ec28       sub rsp, 0x28
│       ╎   0x140001744      e863180000     call 0x140002fac
│       ╎   0x140001749      4883c428       add rsp, 0x28
│       └─< 0x14000174d      e952feffff     jmp 0x1400015a4
..
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: present — claim only: DYNAMIC_BASE set but no .reloc section — loads at preferred base
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: present — Data Execution Prevention flag set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 3
  createprocessa @ 0x1400011fe (?)
  heapalloc @ 0x140005a0d (fcn.1400059b8)
  heapalloc @ 0x140005ac7 (fcn.140005a70)

## revai_tools_audit (pe, revai_tools_audit)

<!-- evidence_assembler: used 9441/60000 chars across 12 tools -->