## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=65fdb5d460b07927 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=89, sha256=65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b
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

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 2 functions (asm)
  ### 0x0040141a
```c
┌ 235: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_5ch @ ebp-0x5c
│           ; var int32_t var_60h @ ebp-0x60
│           ; var int32_t var_64h @ ebp-0x64
│           ; var int32_t var_68h @ ebp-0x68
│           0x0040141a      55             push ebp
│           0x0040141b      8bec           mov ebp, esp
│           0x0040141d      6aff           push 0xffffffffffffffff
│           0x0040141f      68d0b04000     push 0x40b0d0
│           0x00401424      68b42b4000     push 0x402bb4
│           0x00401429      64a100000000   mov eax, dword fs:[0]
│           0x0040142f      50             push eax
│           0x00401430      6489250000..   mov dword fs:[0], esp
│           0x00401437      83ec58         sub esp, 0x58
│           0x0040143a      53             push ebx
│           0x0040143b      56             push esi
│           0x0040143c      57             push edi
│           0x0040143d      8965e8         mov dword [var_18h], esp
│           0x00401440      ff152cb04000   call dword [sym.imp.KERNEL32.dll_GetVersion] ; 0x40b02c ; DWORD GetVersion(void)
│           0x00401446      33d2           xor edx, edx
│           0x00401448      8ad4           mov dl, ah
│           0x0040144a      891540974000   mov dword [0x409740], edx   ; [0x409740:4]=0
│           0x00401450      8bc8           mov ecx, eax
│           0x00401452      81e1ff000000   and ecx, 0xff               ; 255
│           0x00401458      890d3c974000   mov dword [0x40973c], ecx   ; [0x40973c:4]=0
│           0x0040145e      c1e108         shl ecx, 8
│           0x00401461      03ca           add ecx, edx
│           0x00401463      890d38974000   mov dword [0x409738], ecx   ; [0x409738:4]=0
│           0x00401469      c1e810         shr eax, 0x10
│           0x0040146c      a334974000     mov dword [0x409734], eax   ; [0x409734:4]=0
│           0x00401471      33f6           xor esi, esi
│           0x00401473      56             push esi
│           0x00401474      e8e4150000     call 0x402a5d
│           0x00401479      59             pop ecx
│           0x0040147a      85c0           test eax, eax
│       ┌─< 0x0040147c      7508           jne 0x401486
│       │   0x0040147e      6a1c           push 0x1c                   ; 28
│       │   0x00401480      e8b00000
```
  ### 0x00401000
```c
;-- section..text:
            ; CALL XREF from entry0 @ 0x4014e3(x)
┌ 669: int main (int argc, char **argv, char **envp);
│           ; var int32_t var_8h @ ebp-0x4
│           ; var int32_t var_ch @ esp+0x40
│           ; var int32_t var_dh @ esp+0x41
│           ; var int32_t var_b0h_2 @ esp+0xd4
│           ; var int32_t var_b8h_2 @ esp+0xd8
│           ; var int32_t var_14h @ esp+0xe8
│           ; var int32_t var_b0h @ esp+0xec
│           ; var int32_t var_b8h @ esp+0xf0
│           ; var int32_t var_c0h @ esp+0xf4
│           ; var int32_t var_10h @ esp+0x100
│           ; var int32_t var_24h @ esp+0x130
│           ; var int32_t var_25h @ esp+0x131
│           0x00401000      81ece0000000   sub esp, 0xe0               ; [00] -r-x section size 20480 named .text
│           0x00401006      56             push esi
│           0x00401007      57             push edi
│           0x00401008      b930000000     mov ecx, 0x30               ; '0' ; 48
│           0x0040100d      33c0           xor eax, eax
│           0x0040100f      8d7c2425       lea edi, [var_25h]
│           0x00401013      c644242400     mov byte [var_24h], 0
│           0x00401018      f3ab           rep stosd dword es:[edi], eax
│           0x0040101a      66ab           stosw word es:[edi], ax
│           0x0040101c      8d442424       lea eax, [var_24h]
│           0x00401020      68c4db4000     push 0x40dbc4               ; "us7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7j"
│           0x00401025      50             push eax
│           0x00401026      e847030000     call 0x401372
│           0x0040102b      83c408         add esp, 8
│           0x0040102e      6a00           push 0
│           0x00401030      6a00           push 0
│           0x00401032      ff1500b04000   call dword [sym.imp.KERNEL32.dll_GetModuleHandleA] ; 0x40b000 ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)
│           0x00401038      50             push eax
│           0x00401039      68b0104000     push 0x4010b0
│           0x0040103e      6a0e           push 0xe                    ; 14
│           0x00401040      ff15b0b04000   call dword [sym.imp.USER32.dll_SetWindowsHookExA] ; 0x40b0b0 ; "R\xb6" ; HHOOK SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
│           0x00401046      8b35b4b04000   mov esi, dword [sym.imp.USER32.dll_GetMessageA] ; [0x40b0b4:4]=0xb644 reloc.USER32.dll_GetMessageA ; "D\xb6"
│           0x0040104c      6a00           push 0
│           0x0
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r

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

## revai_tools_audit (pe, revai_tools_audit)

<!-- evidence_assembler: used 12658/60000 chars across 12 tools -->