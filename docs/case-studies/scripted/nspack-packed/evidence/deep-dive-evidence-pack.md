## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=2627682eb7e8180f | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=52, sha256=2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5
  Anomalies (16): CrossSectionJump×2 (code), DataBetweenHeaderAndFirstSection (headers), ExtraSpaceAfterResourcesDataDirectory (resources), GuiSubsystemNoWindowApi (headers), HugeFunctionGapAtSectionBoundary (code), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), InvalidSizeOfUninitializedData (sections), Packed×2 (packers), PointerToRawDataNotAligned (sections), SectionNameUnknown×2 (sections), SectionWX×2 (sections), SizeOfRawDataNotAligned×2 (sections), UnbalancedVirtualPhysicalRatio (sections), UnreferencedImports×11 (imports), UnsignedMicrosoft×3 (integrity)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@156
  YARA (info, 3 total): MSVC_2002_linker, nspack_23_02, nspack_23_03
  Functions (7): EntryPoint@27, sub_1025a56@150102, sub_1025d7f@150911, sub_1025e1e@151070, sub_1025dfe@151038, sub_1025e08@151048, sub_1025e1a@151066
  Top high-signal imports (score≥8, 2 of 11):
    [8] kernel32.VirtualAlloc
    [8] kernel32.VirtualProtect
  Mid-signal imports: kernel32.LoadLibraryA, kernel32.GetProcAddress, advapi32.RegOpenKeyExA
  (low-signal/noise imports: 6 omitted)
  Strings/apis (14 total): OriginalFilename, FileDescription, StringFileInfo, FileVersion, GetProcAddress, VarFileInfo, LoadLibraryA, VirtualProtect, VirtualAlloc, VirtualFree, RegOpenKeyExA, GetMenu, SetBkColor, ExitProcess
  Strings (other, 286 items, omitted)
  Carved files (8): DIB@126040 (744 bytes), DIB@126784 (296 bytes), DIB@127080 (3752 bytes), DIB@130832 (2216 bytes), DIB@133048 (1384 bytes), DIB@134432 (9640 bytes), DIB@144072 (4264 bytes), DIB@148336 (1128 bytes)
  Virtual files (11): ICO/1/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, ICO/5/en-us, ICO/6/en-us, ICO/7/en-us, ICO/8/en-us, GRPICO/SC/en-us, VER/1/en-us
  Recovered structures (85): MZ, PE, OptionalHeader, Sections, Resources, Resources.ICO, Resources.ICO.1, Resources.ICO.1.en-us, Resources.ICO.2, Resources.ICO.2.en-us, Resources.ICO.3, Resources.ICO.3.en-us, Resources.ICO.4, Resources.ICO.4.en-us, Resources.ICO.5
  Decompilations (3 top functions):
    ### 27 (EntryPoint, score=?)
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}
```
    ### 150102 (sub_1025a56, score=?)
```c
sub_1025a56 {
    // Error while decompiling : not a valid ea
}
```
    ### 150911 (sub_1025d7f, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_1025d7f(uint8_t *param_1,uint8_t *param_2)

{
    char cVar1;
    undefined4 uVar3;
    uint8_t *puVar4;
    int32_t extraout_ECX;
    int32_t extraout_ECX_00;
    int32_t extraout_ECX_01;
    int32_t extraout_ECX_02;
    int32_t extraout_ECX_03;
    int32_t iVar5;
    uint8_t *puVar6;
    undefined in_CF;
    bool bVar7;
    uint8_t uVar8;
    uint8_t uVar2;
    
    do {
        puVar6 = param_1 + 1;
        *param_2 = *param_1;
        param_2 = param_2 + 1;
        while (sub_1025dfe(), param_1 = puVar6, in_CF) {
            bVar7 = false;
            sub_1025dfe();
            if (bVar7) {
                uVar8 = false;
                uVar3 = sub_1025dfe();
                if (!uVar8) {
                    puVar4 = CONCAT31(uVar3 >> 8, *puVar6) >> 1;
                    if (puVar4 == 0x0) {
                        return;
                    }
                    iVar5 = extraout_ECX + 2 + ((*puVar6 & 1) != 0);
                    puVar6 = puVar6 + 1;
                    goto code_r0x01025df4;
                }
                do {
                    uVar3 = sub_1025dfe();
                    uVar2 = uVar3;
                    bVar7 = CARRY1(uVar2 * '\x02', uVar8);
                    in_CF = CARRY1(uVar2, uVar2) || bVar7;
                    cVar1 = uVar2 * '\x02' + uVar8;
                    puVar4 = CONCAT31(uVar3 >> 8, cVar1);
                    uVar8 = in_CF;
                } while (!CARRY1(uVar2, uVar2) && !bVar7);
                iVar5 = extraout_ECX_00;
                if (cVar1 != '\0') goto code_r0x01025df3;
                *param_2 = 0;
                param_2 = param_2 + 1;
            }
            else {
                func_0x01025e0a();
                if (extraout_ECX_01 == 2) {
                    puVar4 = sub_1025e08();
                    iVar5 = extraout_ECX_02;
                }
                else {
                    puVar6 = puVar6 + 1;
                    puVar4 = 
```

## capa evidence (1 total, showing top 1)
  All rules (1): decompress data using aPLib

## pe_imports (11 imports, 4 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (12)
  Rules: domain, IP, contains_base64, nSpackV2xLiuXingPing, NsPackV2XLiuXingPing, NsPackv23NorthStar, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasModified_DOS_Message, suspicious_packer_section, win_registry

## FLOSS strings (169 total)
  ips (2): version="5.1.0.0", version="6.0.0.0"
  apis (9): LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess, RegOpenKeyExA, SetBkColor, GetMenu
  (other strings, 69 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 3 functions (asm)
  ### 0x0100101b
```c
┌ 5: entry0 ();
└       ┌─< 0x0100101b      e9364a0200     jmp fcn.01025a56
```
  ### 0x01025a56
```c
╎   ; CODE XREF from entry0 @ 0x100101b(x)
├ 648: fcn.01025a56 ();
│       ╎   ; var int32_t var_1beh @ ebp-0x1be
│       ╎   ; var int32_t var_1c2h @ ebp-0x1c2
│       ╎   ; var int32_t var_1c6h @ ebp-0x1c6
│       ╎   ; var int32_t var_1cah @ ebp-0x1ca
│       ╎   ; var int32_t var_1fah @ ebp-0x1fa
│       ╎   ; var int32_t var_202h @ ebp-0x202
│       ╎   ; var int32_t var_212h @ ebp-0x212
│       ╎   ; var int32_t var_22ah @ ebp-0x22a
│       ╎   ; var int32_t var_23eh @ ebp-0x23e
│       ╎   ; var int32_t var_246h @ ebp-0x246
│       ╎   ; var int32_t var_26eh @ ebp-0x26e
│       ╎   ; var int32_t var_27eh @ ebp-0x27e
│       ╎   0x01025a56      9c             pushfd
│       ╎   0x01025a57      60             pushal
│       ╎   0x01025a58      e800000000     call 0x1025a5d
│       ╎   ; CALL XREF from fcn.01025a56 @ 0x1025a58(x)
│       ╎   0x01025a5d      5d             pop ebp
│       ╎   0x01025a5e      b807000000     mov eax, 7
│       ╎   0x01025a63      2be8           sub ebp, eax
│       ╎   0x01025a65      8db5d6fdffff   lea esi, [var_22ah]
│       ╎   0x01025a6b      8b06           mov eax, dword [esi]
│       ╎   0x01025a6d      83f800         cmp eax, 0
│      ┌──< 0x01025a70      7411           je 0x1025a83
│      │╎   0x01025a72  ~   8db5fefdffff   lea esi, [var_202h]
..
│      │╎   0x01025a78      8b06           mov eax, dword [esi]
│      │╎   0x01025a7a      83f801         cmp eax, 1                  ; 1
│     ┌───< 0x01025a7d      0f844b020000   je 0x1025cce
│     │└──> 0x01025a83  ~   c70601000000   mov dword [esi], 1
..
│     │ ╎   0x01025a89      8bd5           mov edx, ebp
│     │ ╎   0x01025a8b      8b8592fdffff   mov eax, dword [var_26eh]
│     │ ╎   0x01025a91      2bd0           sub edx, eax
│     │ ╎   0x01025a93      899592fdffff   mov dword [var_26eh], edx
│     │ ╎   0x01025a99      0195c2fdffff   add dword [var_23eh], edx
│     │ ╎   0x01025a9f      8db506feffff   lea esi, [var_1fah]
│     │ ╎   0x01025aa5      0116           add dword [esi], edx
│     │ ╎   0x01025aa7      8b36           mov esi, dword [esi]
│     │ ╎   0x01025aa9      8bfd           mov edi, ebp
│     │ ╎   0x01025aab      60             pushal
│     │ ╎   0x01025aac      6a40           push 0x40                   ; pe_nt_image_headers32
│     │ ╎   0x01025aae      6800100000     push 0x1000
│     │ ╎   0x01025ab3      6800100000     push 0x1000
│     │ ╎   0x01025ab8      6a00           push 0
│     │ ╎   0x01025aba      ff953afeffff   call dword [var_
```
  ### 0x01025884
```c
│           ;-- (0x01025888) GetProcAddress:
┌ 532: sym.imp.KERNEL32.DLL_LoadLibraryA (int32_t arg_53h, int32_t arg_59h, int32_t arg_78h);
│           ; arg int32_t arg_53h @ ebp+0x53
│           ; arg int32_t arg_59h @ ebp+0x59
│           ; arg int32_t arg_78h @ ebp+0x78
│           ; var int32_t var_48h @ ebp-0x48
│           ; var int32_t var_1beh @ ebp-0x1be
│           ; var int32_t var_1c2h @ ebp-0x1c2
│           ; var int32_t var_1c6h @ ebp-0x1c6
│           ; var int32_t var_1cah @ ebp-0x1ca
│           ; var int32_t var_1fah @ ebp-0x1fa
│           ; var int32_t var_202h @ ebp-0x202
│           ; var int32_t var_212h @ ebp-0x212
│           ; var int32_t var_22ah @ ebp-0x22a
│           ; var int32_t var_23eh @ ebp-0x23e
│           ; var int32_t var_246h @ ebp-0x246
│           ; var int32_t var_26eh @ ebp-0x26e
│           ; var int32_t var_27eh @ ebp-0x27e
│           0x01025884  ~   9a590200a9..   lcall 0x259, 0xa9000259
│           0x0102588b  ~   00ba590200cb   add byte [edx - 0x34fffda7], bh
│           ;-- VirtualProtect:
..
│           0x01025891      59             pop ecx
│           0x01025892      0200           add al, byte [eax]
│           ;-- VirtualFree:
│           0x01025894      da5902         ficomp dword [ecx + 2]
│           0x01025897  ~   00e8           add al, ch
│           ;-- ExitProcess:
..
│           0x01025899      59             pop ecx
│           0x0102589a      0200           add al, byte [eax]
│           0x0102589c      0000           add byte [eax], al
│           0x0102589e      0000           add byte [eax], al
│           ;-- ShellAboutW:
│           0x010258a0      f65902         neg byte [ecx + 2]
│           0x010258a3      0000           add byte [eax], al
│           0x010258a5      0000           add byte [eax], al
│           0x010258a7  ~   00045a         add byte [edx + ebx*2], al
│           ;-- __CxxFrameHandler:
..
│           0x010258aa      0200           add al, byte [eax]
│           0x010258ac      0000           add byte [eax], al
│           0x010258ae      0000           add byte [eax], al
│           ;-- RegOpenKeyExA:
│           0x010258b0      185a02         sbb byte [edx + 2], bl
│           0x010258b3      0000           add byte [eax], al
│           0x010258b5      0000           add byte [eax], al
│           0x010258b7  ~   0028           add byte [eax], ch
│           ;-- SetBkColor:
..
│           0x010258b9      5a             pop edx
│           0x010258ba      0200   
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000040 PE..L.....};..........................

<!-- evidence_assembler: used 10605/60000 chars across 9 tools -->