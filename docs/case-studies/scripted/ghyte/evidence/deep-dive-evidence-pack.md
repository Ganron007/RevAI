## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=a59b2cb9f6c70663 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=91, sha256=a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567
  Anomalies (4): HugeGapBetweenFunctions (code), NoChecksum (integrity), NoValidCertificate (integrity), XorInLoop (code)
  High-signal anomaly locations: NoChecksum@328; XorInLoop@8221
  YARA (info, 2 total): MSVC_2005_linker, MSVC_2008_rich
  Functions (8): sub_402bdb@8155, sub_403051@9297, sub_401686@2694, EntryPoint@2688, sub_4017bb@3003, sub_401198@1432, sub_402ebf@8895, sub_402a06@7686
  Mid-signal imports: user32.SendMessageA, kernel32.GetModuleHandleA
  (low-signal/noise imports: 22 omitted)
  Strings/apis (17 total): DestroyWindow, GetModuleHandleA, SendMessageA, GetMessageA, GetLastError, GetCommandLineA, RegisterClassExA, LoadCursorA, GetWindowRect, ShowWindow, SetTimer, UpdateWindow, LoadBitmapA, CreateWindowExA, DefWindowProcA
  Strings (other, 153 items, omitted)
  Carved files (2): DIB@18064 (10036 bytes), DIB@28128 (216 bytes)
  Virtual files (4): BMP/101/en-us, ICO/1/en-us, GRPICO/100/en-us, MANIF/1/en-us
  Recovered structures (30): MZ, RichHeader, PE, OptionalHeader, Sections, gdi32.FT, kernel32.FT, user32.FT, ImportTable, gdi32.OFT, kernel32.OFT, user32.OFT, ImportNames, Resources, Resources.BMP
  Decompilations (3 top functions):
    ### 8155 (sub_402bdb, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_402bdb(void)

{
    uint8_t uVar1;
    uint8_t uVar2;
    uint32_t uVar3;
    int32_t iVar4;
    uint32_t uVar5;
    int32_t *piVar6;
    int32_t *piVar7;
    int32_t *piVar8;
    int32_t *piVar9;
    uint8_t *puVar10;
    uint8_t *puVar11;
    
    piVar8 = 0x4044cc + 1;
    puVar10 = piVar8 + *0x4044cc;
    piVar6 = puVar10 + -1;
    iVar4 = ([0x0x4044c8] - *0x4044cc) + -4;
    piVar7 = piVar8;
    004044c8 = iVar4;
    piRam004044cc = puVar10;
    do {
        *puVar10 = *puVar10 ^ [0x0x4041fc] + *piVar7;
        piVar9 = piVar8;
        if (piVar7 != piVar6) {
            piVar9 = piVar7 + 1;
        }
        puVar10 = puVar10 + 1;
        iVar4 = iVar4 + -1;
        piVar7 = piVar9;
    } while (iVar4 != 0);
    (*user32.SendMessageA)([0x0x404468], 0x111, 0x4044c8, 0x39);
    iVar4 = [0x0x4044c8];
    puVar10 = 0x4044bc;
    puVar11 = 0x4044cc;
    do {
        *puVar11 = *puVar10;
        puVar10 = puVar10 + 1;
        puVar11 = puVar11 + 1;
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    0040444c = [0x0x4041f3] + 0x4041f7;
    piVar7 = 0x4041f7 + 1;
    piVar6 = piVar7 + *0x4041f7;
    puVar10 = piVar7 + *0x4041f7;
    uVar5 = 0;
    uVar3 = *piVar7 + 1;
    puVar11 = 0x4044bc;
    piRam00404448 = piVar6;
    while( true ) {
        if (piVar6 <= piVar7) {
            for (iVar4 = [0x0x40444c] - puVar10; iVar4 != 0; iVar4 = iVar4 + -1) {
                *puVar11 = *puVar10;
                puVar10 = puVar10 + 1;
                puVar11 = puVar11 + 1;
            }
            return;
        }
        if (uVar3 < uVar5) break;
        for (iVar4 = uVar3 - uVar5; iVar4 != 0; iVar4 = iVar4 + -1) {
            *puVar11 = *puVar10;
            puVar10 = puVar10 + 1;
            puVar11 = puVar11 + 1;
        }
        uVar1 = *(piVar7 + 1);
        uVar2 = *(piVar7 + 2);
        uVar5 = uVar2;
        for (uVar3 = uVar5; uVar3 != 0; uVar3 = uVar3 - 1) {
            *puVar11 = uVar1;
    
```
    ### 9297 (sub_403051, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_403051(undefined4 param_1,int32_t param_2,uint32_t *param_3,int32_t param_4)

{
    undefined uVar1;
    code *pcVar2;
    undefined4 uVar3;
    int32_t iVar4;
    uint32_t uVar5;
    uint32_t uVar6;
    int32_t *piVar7;
    undefined *puVar8;
    code *pcVar9;
    undefined *puVar10;
    uint32_t *puVar11;
    code *pcVar12;
    int32_t *piVar13;
    uint32_t uVar14;
    undefined auStack_30 [4];
    undefined auStack_2c [24];
    int32_t iStack_14;
    int32_t iStack_10;
    int32_t iStack_c;
    int32_t iStack_8;
    
    pcVar2 = kernel32.GetModuleHandleA;
    if (param_2 == 0x401) {
        puVar10 = *param_3;
        puVar8 = param_3[1];
        iVar4 = 7;
        do {
            uVar1 = *puVar10;
            puVar10 = puVar10 + 1;
            *puVar8 = uVar1;
            puVar8 = puVar8 + -param_4;
            iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
        return 0;
    }
    if (param_2 == 1) {
        (*user32.LoadBitmapA)([0x0x4041c7], 0x66);
        00404458 = (*kernel32.GetLastError)();
        iVar4 = [0x0x4041c7];
        (*user32.CreateWindowExA)(0, "button", "summer", 0x10010000, 0xc, 10, 0x154, 0x26, param_1, 2, [0x0x4041c7], 0);
        00404440 = (*kernel32.GetLastError)();
        0040445c = 00404440;
        004044d4 = 00404440;
        00404454 = (*user32.CreateWindowExA)(0, "edit", 0, 0x40000000, 5, 0x4a, 500, 0x1ae, param_1, 1, iVar4, 0);
        004041e3 = (*kernel32.GetLastError)();
        (*user32.CreateWindowExA)(0, "button", "summer", 0x40000001, 5, 0x17c, 0xba, 0x22, 1, 2, iVar4, 0);
        004041e3 = (*kernel32.GetLastError)();
        0040445c = 004041e3;
        00404464 = (*user32.SendMessageA)(param_1, 0x111, 0x40419d, 0x31);
        (*user32.SendMessageA)(param_1, 0x111, 00404464, 0x2e);
        return 0;
    }
    if (param_2 == 0x113) {
        00404440 = [0x0x404440] + [0x0x404458];
        (*user32.SendMessageA)(param_1, 0x111, 0, 00404440);

```
    ### 2694 (sub_401686, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401686(void)

{
    char cVar1;
    
    00404474 = (*kernel32.GetCommandLineA)();
    004041c7 = (*kernel32.GetModuleHandleA)(0);
    [0x0x4043f0] = 0x30;
    [0x0x4043f4] = 2;
    0x4043f8 = sub_403051;
    [0x0x4043fc] = 0;
    [0x0x404400] = 0;
    puRam004041cf = &stack0xfffffffc;
    00404404 = 004041c7;
    0040440c = (*user32.LoadCursorA)(0, 0x7f00);
    00404408 = (*user32.LoadIconA)(0, 0x7f00);
    [0x0x404418] = "lunt";
    [0x0x404410] = 0xf;
    0040441c = 00404408;
    (*user32.RegisterClassExA)(0x4043f0);
    00404468 = (*user32.CreateWindowExA)
                             (0, "lunt", 0x4043e7, 0xcf0000, 0xfffff8f8, 0xfffff862, 0x1fe, 0x1e0, 0, 0, [0x0x4041c7]
                              , 0);
    (*user32.ShowWindow)(00404468, 5);
    (*user32.UpdateWindow)([0x0x404468]);
    while( true ) {
        cVar1 = (*user32.GetMessageA)(0x404420, 0, 0, 0);
        if (cVar1 == '\0') break;
        (*user32.TranslateMessage)(0x404420);
        (*user32.DispatchMessageA)(0x404420);
    }
    sub_402a06();
    return;
}
```

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encrypt data using RC4 PRGA
  ATT&CK {'parts': ['Execution', 'Command and Scripting Interpreter'], 'tactic': 'Execution', 'technique': 'Command and Scripting Interpreter', 'subtechnique': '', 'id': 'T1059'} (1): accept command line arguments
  ATT&CK {'parts': ['Defense Evasion', 'Hide Artifacts', 'Hidden Window'], 'tactic': 'Defense Evasion', 'technique': 'Hide Artifacts', 'subtechnique': 'Hidden Window', 'id': 'T1564.003'} (1): hide graphical window

## pe_imports (24 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (7)
  Rules: domain, contains_base64, IsPE32, IsWindowsGUI, HasRichSignature, Safeguard_103_Simonzh, ZProtect_v144_lifeengines

## FLOSS strings (72 total)
  apis (17): DestroyWindow, SetTimer, SetWindowPos, GetWindowRect, LoadCursorA, LoadIconA, SendMessageA, DefWindowProcA, RegisterClassExA, CreateWindowExA, LoadBitmapA, GetMessageA
  (other strings, 53 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 2 functions (asm)
  ### 0x00401680
```c
┌ 6: entry0 ();
│           0x00401680      e801000000     call fcn.00401686
└           0x00401685      c3             ret
```
  ### 0x00401686
```c
; CALL XREF from entry0 @ 0x401680(x)
┌ 299: fcn.00401686 ();
│           0x00401686      55             push ebp
│           0x00401687      8bec           mov ebp, esp
│           0x00401689      ff150c404000   call dword [sym.imp.kernel32.dll_GetCommandLineA] ; 0x40400c ; "0M" ; LPSTR GetCommandLineA(void)
│           0x0040168f      a374444000     mov dword [0x404474], eax   ; [0x404474:4]=0
│           0x00401694      6a00           push 0
│           0x00401696      ff1508404000   call dword [sym.imp.kernel32.dll_GetModuleHandleA] ; 0x404008 ; "BM" ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)
│           0x0040169c      892dcf414000   mov dword [0x4041cf], ebp   ; [0x4041cf:4]=97 ; "a"
│           0x004016a2      a304444000     mov dword [0x404404], eax   ; [0x404404:4]=0
│           0x004016a7      a3c7414000     mov dword [0x4041c7], eax   ; [0x4041c7:4]=17
│           0x004016ac      c705f04340..   mov dword [0x4043f0], 0x30  ; '0'
│                                                                      ; [0x4043f0:4]=0
│           0x004016b6      c705f44340..   mov dword [0x4043f4], 2     ; [0x4043f4:4]=0
│       ┌─< 0x004016c0      eb04           jmp 0x4016c6
..
│       │   ; CODE XREF from fcn.00401686 @ 0x4016c0(x)
│       └─> 0x004016c6      c705f84340..   mov dword [0x4043f8], 0x403051 ; 'Q0@'
│                                                                      ; [0x4043f8:4]=0
│           0x004016d0      c705fc4340..   mov dword [0x4043fc], 0     ; [0x4043fc:4]=0
│           0x004016da      c705004440..   mov dword [0x404400], 0     ; [0x404400:4]=0
│           0x004016e4      68007f0000     push 0x7f00
│           0x004016e9      6a00           push 0
│           0x004016eb      ff1534404000   call dword [sym.imp.user32.dll_LoadCursorA] ; 0x404034 ; "4L" ; HCURSOR LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName)
│           0x004016f1      a30c444000     mov dword [0x40440c], eax   ; [0x40440c:4]=0
│           0x004016f6      68007f0000     push 0x7f00
│           0x004016fb      6a00           push 0
│           0x004016fd      ff1518404000   call dword [sym.imp.user32.dll_LoadIconA] ; 0x404018 ; "BL" ; HICON LoadIconA(HINSTANCE hInstance, LPCSTR lpIconName)
│           0x00401703      a308444000     mov dword [0x404408], eax   ; [0x404408:4]=0
│           0x00401708      a31c444000     mov dword [0x40441c], eax   ; [0x40441c:4]=0
│           0x0040170d      c705184440..   mov dword [0x404418], 0x40439a ; [0x404418:4]=0
│         
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: missing — Data Execution Prevention flag not set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 0

## revai_tools_audit (pe, revai_tools_audit)

<!-- evidence_assembler: used 11237/60000 chars across 12 tools -->