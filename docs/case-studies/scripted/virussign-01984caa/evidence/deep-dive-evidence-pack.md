## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=6878836f0ab5bdf0 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=87, sha256=6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d
  Anomalies (11): BigBufferNoXrefMediumToHighEntropy×6 (entropy), BoundImports (imports), CodeSectionNotExecutable (sections), DataBetweenHeaderAndFirstSection (headers), EmptyExportTable (exports), EntryPointInNonExecRegion (code), ExportTimeDifferentThanTimeDateStamp (time), InvalidChecksum (integrity), SectionGap (sections), SectionWeirdRights (sections), TruncatedPEFile (integrity)
  YARA (info, 4 total): MSVC_6_linker, MSVC_6_rich, VisualBasic, ms_visual_basic_50_60_01
  Functions (2): EntryPoint@5076, jmp_msvbvm60.ThunRTMain@5068
  Top high-signal imports (score≥8, 1 of 67):
    [10] msvbvm60.__vbaAryDestruct ×2
  (low-signal/noise imports: 66 omitted)
  Strings/urls (3 total): zhttp://ns.adobe.com/xap/1.0/, IEC http://www.iec.ch
  Strings/paths (1 total): C:\Program Files..dio\VB98\VB6.OLB
  Strings/apis (8 total): SetLayeredWindowAttributes, GetWindowLongA, SetWindowLongA, OriginalFilename, StringFileInfo, FileVersion, DllFunctionCall, VarFileInfo
  Strings (other, 288 items, omitted)
  Carved files (3): JPEG@5613 (3611 bytes), JPEG@11468 (3611 bytes), DIB@184552 (292552 bytes)
  Virtual files (3): ICO/1/unk, GRPICO/1/unk, VER/1/zh-cn
  Recovered structures (26): MZ, RichHeader, PE, OptionalHeader, Sections, BoundImportTable, msvbvm60.FT, ExportDirectory, VBForms, VBHeader, ImportTable, msvbvm60.OFT, ImportNames, Resources, Resources.ICO
  Decompilations (2 top functions):
    ### 5076 (EntryPoint, score=?)
```c
/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x004015c0) overlaps instruction at (ram,0x004015bf)
    */
/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Type propagation algorithm not settling */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    int32_t *piVar1;
    uint32_t uVar2;
    uint8_t *puVar3;
    undefined4 uVar4;
    char cVar5;
    uint8_t uVar6;
    uint8_t uVar7;
    uint8_t uVar8;
    uint32_t *puVar9;
    int32_t *piVar10;
    char **ppcVar11;
    unkbyte3 Var20;
    char *pcVar14;
    uint32_t uVar15;
    int32_t iVar16;
    uint8_t *puVar17;
    char **ppcVar18;
    int32_t iVar19;
    uint8_t uVar21;
    char cVar23;
    int32_t extraout_ECX;
    char *pcVar22;
    uint8_t uVar24;
    undefined2 uVar25;
    uint8_t *puVar26;
    char **unaff_EBX;
    char **ppcVar27;
    undefined *puVar28;
    uint32_t unaff_EBP;
    uint32_t uVar29;
    int32_t unaff_ESI;
    undefined4 *puVar30;
    int32_t unaff_EDI;
    uint8_t in_AF;
    undefined8 uVar31;
    undefined2 uStackY_8;
    uint32_t *puVar12;
    uint8_t *puVar13;
    
    uVar31 = jmp_msvbvm60.ThunRTMain("VB5!6&vb6chs.dll");
    ppcVar27 = uVar31 >> 0x20;
    piVar10 = uVar31;
    uVar8 = uVar31;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 ^ uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    puVar30 = unaff_ESI + 1;
    pcVar22 = extraout_ECX + -1;
    uVar25 = uVar31 >> 0x20;
    uVar21 = uVar31 >> 0x28;
    cVar5 = unaff_EBX;
    if (pcVar22 == 0x0) {
        out(*puVar30, uVar25);
        uVar4 = *(unaff_ESI + 5);
        ff4ad58a = uVar8;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + unaff_EBX;
        *unaff_E
```
    ### 5068 (jmp_msvbvm60.ThunRTMain, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_msvbvm60.ThunRTMain(void)

{
    /* WARNING: Could not recover jumptable at 0x004013cc. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*msvbvm60.ThunRTMain)();
    return;
}
```

## capa evidence (1 total, showing top 1)
  All rules (1): compiled from Visual Basic

## pe_imports (0 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (16)
  Rules: domain, IP, contains_base64, url, IsPE32, IsWindowsGUI, HasOverlay, IsBeyondImageSize, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60, Microsoft_Visual_Basic_v50_additional, Microsoft_Visual_Basic_v50v60_additional, SEH__vba, SEH_Init

## FLOSS strings (437 total)
  urls (1): zhttp://ns.adobe.com/xap/1.0/
  (other strings, 79 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 4 functions (asm)
  ### 0x004013d4
```c
┌ 92: entry0 ();
│           0x004013d4      68e4914200     push 0x4291e4               ; "VB5!6&vb6chs.dll"
│           0x004013d9      e8eeffffff     call sub.MSVBVM60.DLL_ThunRTMain
│           0x004013de      0000           add byte [eax], al
│           0x004013e0      0000           add byte [eax], al
│           0x004013e2      0000           add byte [eax], al
│           0x004013e4      3000           xor byte [eax], al
│           0x004013e6      0000           add byte [eax], al
│           0x004013e8      3800           cmp byte [eax], al
│           0x004013ea      0000           add byte [eax], al
│           0x004013ec      0000           add byte [eax], al
│           0x004013ee      0000           add byte [eax], al
│           0x004013f0      a6             cmpsb byte [esi], byte es:[edi]
│       ┌─< 0x004013f1      e27e           loop 0x401471
│       │   0x004013f3      fb             sti
│       │   0x004013f4      9b             wait
│       │   0x004013f5      6f             outsd dx, dword [esi]
│       │   0x004013f6      53             push ebx
│       │   0x004013f7      4d             dec ebp
│       │   0x004013f8      a28ad54aff     mov byte [0xff4ad58a], al   ; [0xff4ad58a:1]=255
│       │   0x004013fd      58             pop eax
│       │   0x004013fe      0b16           or edx, dword [esi]
│       │   0x00401400      0000           add byte [eax], al
│       │   0x00401402      0000           add byte [eax], al
│       │   0x00401404      0000           add byte [eax], al
│       │   0x00401406      0100           add dword [eax], eax
│       │   0x00401408      0000           add byte [eax], al
│       │   0x0040140a      0000           add byte [eax], al
│       │   0x0040140c      48             dec eax
│       │   0x0040140d      00fd           add ch, bh
│       │   0x0040140f      07             pop es
│       │   0x00401410      56             push esi
│       │   0x00401411      6231           bound esi, qword [ecx]
│       │   0x00401413      007085         add byte [eax - 0x7b], dh
│       │   0x00401416      2903           sub dword [ebx], eax
│       │   0x00401418      0000           add byte [eax], al
│      ┌──> 0x0040141a      0000           add byte [eax], al
│      ╎│   0x0040141c      ffcc           dec esp
│      ╎│   0x0040141e      3100           xor dword [eax], eax
│      ╎│   0x00401420      048c           add al, 0x8c                ; 140
│      ╎│   0x00401422      2d5b5eb187     sub eax, 0x87b15e
```
  ### 0x004013cc
```c
; CALL XREF from entry0 @ 0x4013d9(x)
┌ 6: sub.MSVBVM60.DLL_ThunRTMain ();
└           0x004013cc      ff25dc104000   jmp dword [sym.imp.MSVBVM60.DLL_ThunRTMain] ; 0x4010dc
```
  ### 0x00401000
```c
╎╎   ;-- section..text:
┌ 619: sym.imp.MSVBVM60.DLL__CIcos ();
│      ╎╎   0x00401000  ~   8693a372f909   xchg byte [ebx + 0x9f972a3], dl ; [00] srwx section size 176128 named .text
│      ╎╎   ;-- _adj_fptan:
..
│      ╎╎   0x00401006  ~   a372ee6aa4     mov dword [0xa46aee72], eax ; [0xa46aee72:4]=-1
│      ╎╎   ;-- __vbaVarMove:
..
│      ╎╎   ;-- (0x0040100c) __vbaFreeVar:
│     ┌───< 0x0040100b  ~   7231           jb 0x40103e
│     │╎╎   ;-- (0x00401010) rtcRgb:
│     │╎╎   0x0040100d  ~   68a4728dcc     push 0xcc8d72a4
│    ┌────> 0x00401012  ~   a1726272a4     mov eax, dword [0xa4726272] ; [0xa4726272:4]=-1
│    ╎│╎╎   ;-- __vbaFreeVarList:
│   ┌─────> 0x00401014      6272a4         bound esi, qword [edx - 0x5c]
│   ╎╎│╎│   ;-- (0x00401018) __vbaEnd:
│   ╎╎│╎└─< 0x00401017  ~   7288           jb 0x400fa1
│   ╎╎│╎    0x00401019  ~   bea072ba02     mov esi, 0x2ba72a0
│   ╎╎│╎    ;-- _adj_fdiv_m64:
│   ╎╎│╎    ;-- (0x00401020) __vbaFreeObjList:
│   ╎╎│╎    0x0040101c  ~   ba02a372c3     mov edx, 0xc372a302
│   ╎╎│╎    0x00401021      9f             lahf
│   ╎╎│╎    0x00401022  ~   a1724109a3     mov eax, dword [0xa3094172] ; [0xa3094172:4]=-1
│   ╎╎│╎│   ;-- _adj_fprem1:
..
│   ╎╎│╎│   ;-- (0x00401028) __vbaStrCat:
│   ╎╎│╎│   0x00401025  ~   09a372766aa2   or dword [ebx - 0x5d95898e], esp
│   ╎╎│╎│   0x00401029      6aa2           push 0xffffffffffffffa2
│   ╎╎│╎│   ;-- (0x0040102c) __vbaSetSystemError:
│  ┌──────< 0x0040102b  ~   723a           jb 0x401067
│  │╎╎│╎│   0x0040102d      c3             ret
..
│ ││╎╎│╎│   ;-- (0x00401040) rtcRandomize:
│ ││╎╎└───> 0x0040103e  ~   a1723acda1     mov eax, dword [0xa1cd3a72] ; [0xa1cd3a72:4]=-1
│ ││╎╎│││   ;-- (0x00401044) __vbaOnError:
│ ─────└──< 0x00401043  ~   729d           jb 0x400fe2
│ ││╎╎│ │   0x00401045      49             dec ecx
│ ││╎╎│ │   0x00401046  ~   a272f19fa1     mov byte [0xa19ff172], al   ; [0xa19ff172:1]=255
│ ││╎╎│ │   ;-- __vbaObjSet:
..
│ ││╎╎│┌──< 0x0040104b  ~   7206           jb 0x401053                 ; sym.imp.MSVBVM60.DLL__CIcos+0x53
│ ││╎╎│││   ;-- _adj_fdiv_m16i:
..
│ ││╎╎│││   ;-- (0x00401050) _adj_fdivr_m16i:
│ ││╎╎│││   0x0040104d  ~   03a3720604a3   add esp, dword [ebx - 0x5cfbf98e]
│ ││╎╎│││   ;-- (0x00401054) _CIsin:
│ ─────└──> 0x00401053  ~   72ee           jb 0x401043
│ ││╎╎│ │   0x00401055      94             xchg esp, eax
│ ││╎╎│ │   0x00401056  ~   a372ea62a3     mov dword [0xa362ea72], eax ; [0xa362ea72:4]=-1
│ ││╎╎│ │   ;-- __vbaChkstk:
..
│ ││╎╎│┌──< 0x004010
```
  ### 0x00401030
```c
┌ 64: sym.imp.MSVBVM60.DLL___vbaHresultCheckObj ();
│     ╎╎└─< 0x00401030      74a2           je 0x400fd4
│     ╎╎    ;-- (0x00401034) _adj_fdiv_m32:
│     ╎╎    0x00401032  ~   a1726e02a3     mov eax, dword [0xa3026e72] ; [0xa3026e72:4]=-1
│     ╎╎    ;-- (0x00401038) __vbaAryDestruct:
│     ╎╎ ─> 0x00401037  ~   72fe           jb 0x401037
│     ╎╎    0x00401039  ~   c1a17205cd..   shl dword [ecx - 0x5e32fa8e], 0x72
│     ╎╎    ;-- (0x0040103c) rtcRandomNext:
│     ╎╎┌─> 0x0040103a  ~   a17205cda1     mov eax, dword [0xa1cd0572] ; [0xa1cd0572:4]=-1
│     ╎╎╎   ;-- (0x00401040) rtcRandomize:
..
│     ╎╎╎   0x0040103f  ~   723a           jb 0x40107b
│     ╎╎╎   ;-- rtcRandomize:
│     ╎╎╎   0x00401040      3acd           cmp cl, ch
│     ╎╎╎   0x00401042  ~   a1729d49a2     mov eax, dword [0xa2499d72] ; [0xa2499d72:4]=-1
│   ╎╎╎╎╎   ;-- __vbaOnError:
..
│   ╎╎╎╎└─< 0x00401047  ~   72f1           jb 0x40103a
│   ╎╎╎╎    ;-- __vbaObjSet:
..
│   ╎╎╎╎    0x00401049      9f             lahf
│   ╎╎╎╎    0x0040104a  ~   a1720603a3     mov eax, dword [0xa3030672] ; [0xa3030672:4]=-1
│   ╎╎╎╎    ;-- _adj_fdiv_m16i:
..
│   ╎╎╎╎    ;-- (0x00401050) _adj_fdivr_m16i:
│   ╎╎╎╎┌─< 0x0040104f  ~   7206           jb 0x401057
│   ╎╎╎╎│   ;-- _adj_fdivr_m16i:
..
│   ╎╎╎╎│   0x00401051      04a3           add al, 0xa3                ; 163
│   │╎╎╎│   ;-- (0x00401054) _CIsin:
..
│    ╎╎╎│   ;-- (0x00401058) __vbaChkstk:
│    ╎╎╎└─> 0x00401057  ~   72ea           jb 0x401043
│    ╎╎╎    ;-- (0x0040105c) __vbaFileClose:
│    ╎╎╎    0x00401059  ~   62a3727d41a1   bound esp, qword [ebx - 0x5ebe828e]
│    ╎╎╎│   0x0040105f  ~   7274           jb 0x4010d5
│    ╎╎╎│   ;-- EVENT_SINK_AddRef:
..
│  │╎╎╎╎│   ;-- (0x00401068) __vbaPutOwner3:
│  │╎╎╎╎│   ;-- (0x00401074) __vbaRedim:
│   ╎╎│╎│   ;-- (0x00401078) __vbaStrR8:
│   ╎╎ ╎│   ;-- (0x0040107c) EVENT_SINK_Release:
│   ╎╎ ╎│   ;-- (0x0040107c) EVENT_SINK_Release:
│   ╎╎ ╎│   0x0040107b  ~   7287           jb sym.imp.MSVBVM60.DLL__adj_fptan
│   ╎╎ ╎│   0x0040107d      9b             wait
..
│    ╎ ╎│   ;-- (0x00401088) _CIsqrt:
│    ╎  │   ;-- (0x00401090) __vbaExceptHandler:
│    ╎  │   ;-- _adj_fprem:
│      ││   ;-- (0x004010a0) __vbaGetOwner3:
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 12206/60000 chars across 9 tools -->