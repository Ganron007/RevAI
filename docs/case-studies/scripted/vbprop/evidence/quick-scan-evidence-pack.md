## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=65fdb5d460b07927 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=5.18, sha256=65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b
  Anomalies (8): CrossSectionJump (code), ExecutableSectionNoCode (sections), GuiSubsystemNoWindowApi (headers), NoChecksum (integrity), SectionWX (sections), SectionWeirdRights (sections), SpaghettiFunction×7 (code), XorInLoop×8 (code)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@308; NoChecksum@304; SpaghettiFunction@5742,8489,9303; XorInLoop@4597,4616,4641
  YARA (info, 4 total): MSVC_6_linker, MSVC_6_rich, msvc_uv_55, msvc_60_07
  Functions (15): sub_401000@4096, jmp_kernel32.RtlUnwind@23410, sub_402afe@11006, sub_402adc@10972, sub_401505@5381, sub_4020b3@8371, sub_402b66@11110, sub_402c71@11377, sub_4052d7@21207, sub_402abc@10940, sub_401558@5464, sub_402b92@11154, __NMSG_WRITE@11461, found_bx@20096, sub_404830@18480
  Top high-signal imports (score≥8, 2 of 49):
    [10] kernel32.HeapDestroy
    [8] kernel32.VirtualAlloc ×4
  Mid-signal imports: kernel32.TerminateProcess, kernel32.GetProcAddress, kernel32.LoadLibraryA, kernel32.GetModuleHandleA
  (low-signal/noise imports: 43 omitted)
    Constants/runtime (11): runtime::msvc_r6027, runtime::msvc_r6026, runtime::msvc_r6025, runtime::msvc_r6024, runtime::msvc_r6019, runtime::msvc_r6018, runtime::msvc_r6017, runtime::msvc_r6016
  Strings/apis (44 total): GetLastActivePopup, GetActiveWindow, OriginalFilename, FileDescription, FreeEnvironmentStringsA, FreeEnvironmentStringsW, StringFileInfo, GetEnvironmentStrings, GetEnvironmentStringsW, GetEnvironmentVariableA, FileVersion, FlushFileBuffers, GetCurrentProcess, UnhookWindowsHookEx, SetStdHandle
  Strings (other, 124 items, omitted)
  Carved files (2): DIB@49432 (3240 bytes), DIB@52672 (9640 bytes)
  Virtual files (4): ICO/1/zh-cn, ICO/2/zh-cn, GRPICO/102/zh-cn, VER/1/zh-cn
  Recovered structures (27): MZ, RichHeader, PE, OptionalHeader, Sections, kernel32.FT, user32.FT, ImportTable, kernel32.OFT, user32.OFT, ImportNames, Resources, Resources.ICO, Resources.GRPICO, Resources.VER
  Decompilations (3 top functions):
    ### 4096 (sub_401000, score=?)
```c
/* WARNING: Possible PIC construction at 0x0040115a: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x0040115f) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401000(void)

{
    code *pcVar1;
    code *pcVar2;
    code *pcVar3;
    uint8_t uVar4;
    uint8_t uVar5;
    undefined4 uVar6;
    int32_t iVar7;
    uint8_t uVar8;
    uint8_t uVar9;
    uint8_t uVar10;
    int32_t iVar11;
    int32_t iVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint8_t uVar15;
    undefined4 unaff_EBX;
    undefined4 *puVar16;
    undefined4 *puVar17;
    undefined4 uVar18;
    undefined uStack_1b4;
    undefined4 uStack_1b3;
    undefined4 uStack_12c;
    undefined4 **ppuStack_128;
    undefined4 uStack_124;
    undefined4 uStack_120;
    undefined4 uStack_11c;
    int32_t *piStack_118;
    int32_t *piStack_114;
    undefined4 *puStack_10c;
    int32_t iStack_108;
    int32_t iStack_104;
    undefined4 uStack_100;
    undefined4 uStack_fc;
    undefined4 uStack_f8;
    undefined4 uStack_f4;
    undefined *puStack_f0;
    undefined4 uStack_ec;
    undefined uStack_c4;
    undefined4 auStack_c3 [48];
    
    uStack_c4 = 0;
    puVar16 = auStack_c3;
    for (iVar11 = 0x30; iVar11 != 0; iVar11 = iVar11 + -1) {
        *puVar16 = 0;
        puVar16 = puVar16 + 1;
    }
    *puVar16 = 0;
    puStack_f0 = &uStack_c4;
    uStack_ec = "us7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7j";
    uStack_f4 = 0x40102b;
    _sprintf();
    uStack_ec = 0;
    puStack_f0 = 0x0;
    uStack_f4 = 0x401038;
    uStack_f4 = (*kernel32.GetModuleHandleA)();
    uStack_f8 = 0x4010b0;
    uStack_fc = 0xe;
    uStack_100 = 0x401046;
    00406000 = (*user32.SetWindowsHookExA)();
    pcVar1 = user32.GetMessageA;
    uStack_100 = 0;
    iStack_104 = 0;
    puStack_10c = &uStack_f4;
    iStack_108 = 0;
    iVar11 = (*user32.GetMessageA)();
    pcVar3 = user32.DispatchMessageA;
    pcVar2 = user32.TranslateMessage;
    uVar18 = [0x0x406000];
    while (0040600
```
    ### 23410 (jmp_kernel32.RtlUnwind, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_kernel32.RtlUnwind(void)

{
    /* WARNING: Treating indirect jump as call */
    (*kernel32.RtlUnwind)();
    return;
}
```
    ### 11006 (sub_402afe, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_402afe(int32_t param_1,int32_t param_2)

{
    int32_t iVar1;
    int32_t iVar2;
    undefined4 *unaff_FS_OFFSET;
    undefined4 uStack_1c;
    code *pcStack_18;
    undefined4 uStack_14;
    int32_t iStack_10;
    
    iStack_10 = param_1;
    pcStack_18 = sub_402adc;
    uStack_1c = *unaff_FS_OFFSET;
    *unaff_FS_OFFSET = &uStack_1c;
    while( true ) {
        iVar1 = *(param_1 + 8);
        iVar2 = *(param_1 + 0xc);
        if ((iVar2 == -1) || (iVar2 == param_2)) break;
        uStack_14 = *(iVar1 + iVar2 * 0xc);
        *(param_1 + 0xc) = uStack_14;
        if (*(iVar1 + 4 + iVar2 * 0xc) == 0) {
            sub_402b92(0x101);
            (**(iVar1 + 8 + iVar2 * 0xc))();
        }
    }
    *unaff_FS_OFFSET = uStack_1c;
    return;
}
```

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  All rules (2): terminate process, set application hook

## pe_imports (49 imports, 3 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (19)
  Rules: domain, IP, contains_base64, IsPE32, IsWindowsGUI, HasOverlay, HasRichSignature, Microsoft_Visual_Cpp_v60, Installer_VISE_Custom_additional, Microsoft_Visual_Cpp_v50v60_MFC_additional, Microsoft_Visual_Cpp_50, Microsoft_Visual_Cpp_v50v60_MFC, Installer_VISE_Custom, Armadillo_v4x, Microsoft_Visual_Cpp, SEH_Save, SEH_Init, win_hook, win_files_operation

## FLOSS strings (132 total)
  apis (32): GetLastActivePopup, GetActiveWindow, GetModuleHandleA, UnhookWindowsHookEx, GetMessageA, SetWindowsHookExA, CallNextHookEx, ExitProcess, TerminateProcess, GetCurrentProcess, GetStartupInfoA, GetCommandLineA
  (other strings, 48 items omitted)

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: missing — Data Execution Prevention flag not set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 9
  heapalloc @ 0x4032b5 (fcn.00403249)
  heapalloc @ 0x403422 (fcn.00403415)
  heapalloc @ 0x403b16 (fcn.00403aba)
  heapalloc @ 0x403c87 (fcn.00403c66)
  heapalloc @ 0x405242 (fcn.004051ce)
  virtualalloc @ 0x403b30 (fcn.00403aba)
  virtualalloc @ 0x403bbc (fcn.00403b6b)
  virtualalloc @ 0x403c97 (fcn.00403c66)
  virtualalloc @ 0x404099 (fcn.00403f5e)

<!-- evidence_assembler: used 7344/28000 chars across 7 tools -->