## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=1196afa54d18ff2d | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=112, sha256=1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0
  Anomalies (10): CrossSectionJump×9 (code), DynamicString (strings), FewStrings (strings), GuiSubsystemNoWindowApi (headers), HugeGapBetweenFunctions×288 (code), ManyUniqueImmediateBytes (code), StackArrayInitialisationX86×12 (code), UnbalancedVirtualPhysicalRatio (sections), UnknownRootResourceDirectoryId (resources), XorInLoop×8 (code)
  High-signal anomaly locations: DynamicString@3342854; GuiSubsystemNoWindowApi@324; ManyUniqueImmediateBytes@3343968; XorInLoop@1596107,1597997,1613686
  YARA (info, 5 total): MSVC_2013_linker, MSVC_2003_rich, msvs2013_12_0_40629_00_update_5_rich, visual_studio_2013_update_1__12_0__also_has_this_build_number_rich, msvc_uv_25
  Functions (15): sub_731260@3343968, sub_58ab6e@1613678, sub_5866cb@1596107, sub_4bf4c7@780487, sub_730360@3340128, sub_586e2d@1597997, sub_58a000@1610752, sub_72f920@3337504, sub_586e55@1598037, sub_4f62a6@1005222, sub_7172ba@3237562, sub_4100f9@62713, sub_49d48a@641162, sub_42b84d@175181, sub_413900@77056
  Top high-signal imports (score≥8, 2 of 125):
    [10] kernel32.VirtualAllocEx
    [8] kernel32.VirtualAlloc ×3
  Mid-signal imports: kernel32.CreatePipe, kernel32.CreateNamedPipeW, kernel32.DeleteFileW, kernel32.LoadLibraryW, advapi32.RegOpenKeyW, kernel32.GetModuleHandleW, kernel32.DuplicateHandle, kernel32.CreateFileW
  (low-signal/noise imports: 115 omitted)
    Constants/oid (35): oid::signedData, oid::spcIndirectDataContext, oid::spcPEImageData, oid::countryName, oid::stateOrProvinceName, oid::localityName, oid::organizationName, oid::commonName
    Constants/hash (1): hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15
  Strings/urls (7 total): ;http://crl.como..nAuthority.crl0q, 2http://crt.como..eSigningCA.crt0$, 2http://crl.como..eSigningCA.crl0t, /http://crt.como..AddTrustCA.crt0$, http://ocsp.comodoca.com0, https://secure.comodo.net/CPS0C
  Strings/ips (2 total): 1.3.9.6
  Strings/apis (64 total): CreatePolyPolygonRgn, SetBoundsRect, OriginalFilename, GetEnhMetaFilePaletteEntries, WritePrivateProfileSectionW, CreateCompatibleBitmap, SystemTimeToFileTime, CreateRectRgnIndirect, FindVolumeMountPointClose, GetNumberOfConsoleInputEvents, StringFileInfo, CreatePatternBrush, FileVersion, FreeLibraryAndExitThread, GetCurrentDirectoryW
  Strings (other, 227 items, omitted)
  Carved files (5): DIB@6018760 (2392 bytes), DIB@6021152 (16936 bytes), DIB@6038088 (4264 bytes), DIB@6042352 (1128 bytes), PKCS7@6050824 (5367 bytes)
  Virtual files (11): BMP/15/en-us, ICO/50/unk, ICO/51/unk, ICO/52/unk, MENU/4/en-us, MENU/5/en-us, GRPICO/11281/unk, VER/1/en-us, MANIF/1/en-us, 241/4/en-us
  Recovered structures (59): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, gdi32.FT, kernel32.FT, user32.FT, msvcrt.FT, ImportTable, advapi32.OFT, gdi32.OFT, kernel32.OFT, user32.OFT
  Decompilations (3 top functions):
    ### 3343968 (sub_731260, score=?)
```c
/* WARNING: Removing unreachable block (ram,0x007313d6) */
/* WARNING: Removing unreachable block (ram,0x007312f8) */
/* WARNING: Removing unreachable block (ram,0x007312ef) */
/* WARNING: Removing unreachable block (ram,0x0073131b) */
/* WARNING: Removing unreachable block (ram,0x00731323) */
/* WARNING: Removing unreachable block (ram,0x00731334) */
/* WARNING: Removing unreachable block (ram,0x0073134a) */
/* WARNING: Removing unreachable block (ram,0x0073133c) */
/* WARNING: Removing unreachable block (ram,0x007315b2) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_731260(void)

{
    int32_t iVar1;
    undefined2 extraout_var;
    uint32_t uVar2;
    uint32_t uVar3;
    undefined2 extraout_var_00;
    uint32_t *puVar4;
    int32_t iVar5;
    uint32_t uStack_70;
    uint32_t uStack_6c;
    uint32_t uStack_68;
    int32_t iStack_5c;
    uint32_t uStack_54;
    int32_t iStack_44;
    int32_t iStack_40;
    uint32_t uStack_3c;
    int32_t iStack_38;
    uint32_t uStack_34;
    undefined4 uStack_30;
    undefined4 uStack_2c;
    uint32_t uStack_28;
    undefined4 uStack_24;
    undefined4 uStack_20;
    uint32_t uStack_1c;
    undefined4 uStack_18;
    uint32_t uStack_14;
    undefined4 uStack_10;
    undefined4 uStack_c;
    uint32_t uStack_8;
    
    uVar2 = [0x0x734038];
    uVar3 = [0x0x734018];
    uStack_14 = [0x0x734010];
    uStack_1c = 0;
    uStack_28 = 0;
    uStack_10 = [0x0x734020];
    iStack_38 = 0x24a;
    uStack_18._2_2_ = [0x0x73400c] >> 0x10;
    uStack_2c = 0;
    uStack_8 = 0;
    uStack_c = 0;
    iVar1 = (*kernel32.VirtualAlloc)(0, 0xb84fe, 0x1000, 0x40, 0, 0);
    uStack_14 = (*kernel32.CreateNamedPipeW)("fhtwfhuwyiwna", 2, 4, 300, 0, 0, 0, 0);
    if ((uStack_10 == 0) && (uVar3 == 0)) {
        uStack_20._0_2_ = uVar2;
        if (((uVar2 & 0xffff) != 0) || (uStack_c != 0)) {
            uStack_1c = uStack_20 + 0x8bU ^ uStack_14;
        }
        iStack_38 = 0x39d;
    }
    uStack_8 = uStack_1c;
    iVar5 = 0x584b30;
```
    ### 1613678 (sub_58ab6e, score=?)
```c
sub_58ab6e {
    // Error while decompiling : not a valid va
}
```
    ### 1596107 (sub_5866cb, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_5866cb(undefined4 param_1,int32_t param_2)

{
    char *pcVar1;
    code *pcVar2;
    uint32_t *in_EAX;
    int32_t extraout_EDX;
    int32_t unaff_EBX;
    uint32_t **unaff_EDI;
    
    do {
        pcVar1 = CONCAT31(param_2 >> 8, 0xd) + 0x230be42;
        *pcVar1 = -*pcVar1;
        *unaff_EDI = in_EAX;
        *in_EAX = *in_EAX ^ CONCAT22(unaff_EBX >> 0x10, CONCAT11(0x80, unaff_EBX));
        pcVar2 = swi(0xd4);
        (*pcVar2)();
        unaff_EBX = *(extraout_EDX + -0x364342eb) * 0x5d;
        in_EAX = CONCAT31(CONCAT22(unaff_EDI + 3 >> 0x10, 0xcd00) >> 8, 0x2b);
        unaff_EDI = 0x57480255;
        param_2 = extraout_EDX;
        aa1ce707 = extraout_EDX;
    } while( true );
}
```

## capa evidence (13 total, showing top 13)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Execution', 'Command and Scripting Interpreter'], 'tactic': 'Execution', 'technique': 'Command and Scripting Interpreter', 'subtechnique': '', 'id': 'T1059'} (1): accept command line arguments
  ATT&CK {'parts': ['Defense Evasion', 'File and Directory Permissions Modification'], 'tactic': 'Defense Evasion', 'technique': 'File and Directory Permissions Modification', 'subtechnique': '', 'id': 'T1222'} (1): set file attributes
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (1): get disk size
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (1): parse PE header
  All rules (8): create pipe, copy file, delete file, get file attributes, write file on Windows, create or open mutex on Windows, allocate or change RWX memory, terminate process

## pe_imports (125 imports, 2 high-signal)
  allocate_memory (VirtualAllocEx) [T1055]
  load_library (LoadLibrary) [T1129]

## YARA matches (13)
  Rules: domain, IP, contains_base64, url, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasOverlay, HasDigitalSignature, HasRichSignature, SEH_Init, win_mutex, win_files_operation

## FLOSS strings (484 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x0072f018
```c
┌ 446: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           ; var int32_t var_24h @ ebp-0x24
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_38h @ ebp-0x38
│           ; var int32_t var_3ch @ ebp-0x3c
│           ; var int32_t var_50h @ ebp-0x50
│           ; var int32_t var_54h @ ebp-0x54
│           ; var int32_t var_80h @ ebp-0x80
│           0x0072f018      6a70           push 0x70                   ; 'p' ; 112
│           0x0072f01a      6890267300     push 0x732690
│           0x0072f01f      e8f8010000     call 0x72f21c
│           0x0072f024      8d4580         lea eax, [var_80h]
│           0x0072f027      50             push eax
│           0x0072f028      ff1554217300   call dword [sym.imp.KERNEL32.dll_GetStartupInfoW] ; 0x732154 ; VOID GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)
│           0x0072f02e      66813d0000..   cmp word [0x400000], 0x5a4d ; 'MZ'
│                                                                      ; [0x400000:2]=0xffff
│       ┌─< 0x0072f037      7527           jne 0x72f060
│       │   0x0072f039      a13c004000     mov eax, dword [0x40003c]   ; [0x40003c:4]=-1
│       │   0x0072f03e      8d8000004000   lea eax, [eax + 0x400000]
│       │   0x0072f044      813850450000   cmp dword [eax], 0x4550     ; 'PE'
│      ┌──< 0x0072f04a      7514           jne 0x72f060
│      ││   0x0072f04c      0fb74818       movzx ecx, word [eax + 0x18]
│      ││   0x0072f050      81f90b010000   cmp ecx, 0x10b              ; 267
│     ┌───< 0x0072f056      7421           je 0x72f079
│     │││   0x0072f058      81f90b020000   cmp ecx, 0x20b              ; 523
│    ┌────< 0x0072f05e      7406           je 0x72f066
│  ┌┌──└└─> 0x0072f060      8365e400       and dword [var_1ch], 0
│  ╎╎││ ┌─< 0x0072f064      eb27           jmp 0x72f08d
│  ╎╎└────> 0x0072f066      83b8840000..   cmp dword [eax + 0x84], 0xe
│  └──────< 0x0072f06d      76f1           jbe 0x72f060
│   ╎ │ │   0x0072f06f      33c9           xor ecx, ecx
│   ╎ │ │   0x0072f071      3988f8000000   cmp dword [eax + 0xf8], ecx
│   ╎ │┌──< 0x0072f077      eb0e           jmp 0x72f087
│   ╎ └───> 0x0072f079      8378740e       cmp dword [eax + 0x74], 0xe
│   └─────< 0x0072f07d      76e1           jbe 0x72f060
│      ││   0x0072f07f      33c9           xor ecx, ecx
│     
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: missing — Data Execution Prevention flag not set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 3
  virtualalloc @ 0x72fa4a (fcn.0072f9d0)
  virtualalloc @ 0x730cf5 (fcn.00730bf0)
  virtualalloc @ 0x73136d (fcn.00731260)

## revai_tools_audit
  error: revai_tools_audit: timeout


<!-- evidence_assembler: used 11184/60000 chars across 12 tools -->