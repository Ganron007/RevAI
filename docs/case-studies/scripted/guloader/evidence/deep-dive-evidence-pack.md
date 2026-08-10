## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=c5e1c2b5307ebcb3 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=73, sha256=c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509
  Anomalies (3): BoundImports (imports), InvalidChecksum (integrity), StackArrayInitialisationX86 (code)
  YARA (info, 5 total): MSVC_6_linker, MSVC_6_rich, VisualBasic, ms_visual_basic_50_60_01, ms_visual_basic_50_01
  Functions (15): EntryPoint@4744, jmp_msvbvm60.__vbaChkstk@4384, jmp_msvbvm60.__vbaExceptHandler@4390, jmp_msvbvm60.__vbaFPException@4396, jmp_msvbvm60.__vbaAryDestruct@4528, jmp_msvbvm60.rtcVarStrFromVar@4534, jmp_msvbvm60.rtcJoin@4558, jmp_msvbvm60.rtcPMT@4564, jmp_msvbvm60.__vbaI2I4@4570, jmp_msvbvm60.rtcMidCharVar@4576, jmp_msvbvm60.__vbaVarTstEq@4582, jmp_msvbvm60.rtcFormatNumber@4588, jmp_msvbvm60.rtcIsNull@4594, jmp_msvbvm60.rtcDoEvents@4600, jmp_msvbvm60.__vbaStrMove@4648
  Top high-signal imports (score≥8, 1 of 60):
    [10] msvbvm60.__vbaAryDestruct
  (low-signal/noise imports: 59 omitted)
    Constants/guid (1): guid::IPictureDisp
  Strings/paths (1 total): C:\Program Files..dio\VB98\VB6.OLB
  Strings/apis (5 total): OriginalFilename, FileDescription, StringFileInfo, FileVersion, VarFileInfo
  Strings (other, 294 items, omitted)
  Carved files (4): ICO@8253 (26030 bytes), DIB@46032 (296 bytes), DIB@46328 (744 bytes), DIB@47072 (304 bytes)
  Virtual files (5): ICO/30001/unk, ICO/30002/unk, ICO/30003/unk, GRPICO/1/unk, VER/1/en-us
  Recovered structures (47): MZ, RichHeader, PE, OptionalHeader, Sections, BoundImportTable, BoundImportNames, msvbvm60.FT, VBExternalTable, VBObj.chippya, VBForms, VBHeader, VBProjectInfo, VBObj.REBALANCES, VBObj.REBALANCES.OptInfos
  Decompilations (3 top functions):
    ### 4744 (EntryPoint, score=?)
```c
/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x0040133b) overlaps instruction at (ram,0x0040133a)
    */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(undefined4 param_1,undefined4 param_2,undefined2 param_3)

{
    uint32_t *puVar1;
    char cVar2;
    uint8_t uVar3;
    uint8_t *puVar4;
    int32_t *piVar5;
    undefined *puVar6;
    char *pcVar7;
    uint32_t uVar8;
    uint8_t *extraout_ECX;
    uint8_t uVar10;
    char *unaff_EBX;
    char *unaff_ESI;
    undefined2 in_DS;
    bool bVar11;
    undefined8 uVar12;
    char *in_stack_0000001c;
    char *in_stack_00000028;
    char *in_stack_0000002c;
    uint8_t *in_stack_00000030;
    int32_t *in_stack_00000034;
    undefined4 *puVar9;
    
    uVar12 = jmp_msvbvm60.ThunRTMain("VB5!6&*");
    pcVar7 = uVar12 >> 0x20;
    puVar4 = uVar12;
    uVar3 = uVar12;
    *puVar4 = *puVar4 + uVar3;
    *puVar4 = *puVar4 + uVar3;
    *puVar4 = *puVar4 + uVar3;
    *puVar4 = *puVar4 ^ uVar3;
    *puVar4 = *puVar4 + uVar3;
    puVar4 = puVar4 + 1;
    cVar2 = puVar4;
    *puVar4 = *puVar4 + cVar2;
    *puVar4 = *puVar4 + cVar2;
    *puVar4 = *puVar4 + cVar2;
    uVar10 = unaff_EBX >> 8;
    *pcVar7 = *pcVar7 + uVar10;
    piVar5 = [0x0x82409c5c] + -0x73f6e718;
    uVar3 = piVar5;
    *piVar5 = *piVar5 + uVar3;
    *extraout_ECX = *extraout_ECX + uVar3;
    *piVar5 = *piVar5 + uVar3;
    puVar4 = pcVar7 + 0x6f;
    bVar11 = CARRY1(*puVar4, uVar3);
    *puVar4 = *puVar4 + uVar3;
    if ((bVar11) || (bVar11)) {
        extraout_ECX[0x26ed4748] = uVar10;
        *piVar5 = *piVar5 + uVar3;
        *piVar5 = *piVar5 + uVar3;
        *piVar5 = *piVar5 + uVar3;
        in_stack_00000030 = extraout_ECX;
        in_stack_00000028 = unaff_EBX;
        in_stack_0000001c = unaff_ESI;
    }
    else {
        ffffff88 = in(param_3);
        if (!bVar11) {
            cVar2 = in_stack_00000034;
            *in_stack_00000034 = *in_stack_00000034 + cVar2;
            
```
    ### 4384 (jmp_msvbvm60.__vbaChkstk, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_msvbvm60.__vbaChkstk(void)

{
    /* WARNING: Treating indirect jump as call */
    (*msvbvm60.__vbaChkstk)();
    return;
}
```
    ### 4390 (jmp_msvbvm60.__vbaExceptHandler, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_msvbvm60.__vbaExceptHandler(void)

{
    /* WARNING: Treating indirect jump as call */
    (*msvbvm60.__vbaExceptHandler)();
    return;
}
```

## capa evidence (1 total, showing top 1)
  All rules (1): compiled from Visual Basic

## pe_imports (46 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (12)
  Rules: domain, contains_base64, IsPE32, IsWindowsGUI, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60, Microsoft_Visual_Basic_v50_additional, Microsoft_Visual_Basic_v50v60_additional, SEH__vba, SEH_Init

## FLOSS strings (175 total)
  paths (1): C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB
  (other strings, 79 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 2 functions (asm)
  ### 0x00401288
```c
┌ 236: entry0 ();
│           0x00401288      6868134000     push 0x401368               ; 'h\x13@' ; "VB5!6&*"
│           0x0040128d      e8f0ffffff     call 0x401282
│           0x00401292      0000           add byte [eax], al
│           0x00401294      0000           add byte [eax], al
│           0x00401296      0000           add byte [eax], al
│           0x00401298      3000           xor byte [eax], al
│           0x0040129a      0000           add byte [eax], al
│           0x0040129c      40             inc eax
│           0x0040129d      0000           add byte [eax], al
│           0x0040129f      0000           add byte [eax], al
│           0x004012a1      0000           add byte [eax], al
│           0x004012a3      003a           add byte [edx], bh
│           0x004012a5      6a88           push 0xffffffffffffff88
│           0x004012a7      37             aaa
│           0x004012a8      a15c9c4082     mov eax, dword [0x82409c5c] ; [0x82409c5c:4]=-1
│           0x004012ad      05e818098c     add eax, 0x8c0918e8
│           0x004012b2      3d8c000000     cmp eax, 0x8c               ; 140
│           0x004012b7      0000           add byte [eax], al
│           0x004012b9      0001           add byte [ecx], al
│           0x004012bb      0000           add byte [eax], al
│           0x004012bd      00426f         add byte [edx + 0x6f], al
│       ┌─< 0x004012c0      7264           jb 0x401326
│      ┌──< 0x004012c2      657261         jb 0x401326
│      ││   0x004012c5      6461           popal
│      ││   0x004012c7      6d             insd dword es:[edi], dx
│      ││   0x004012c8      61             popal
│     ┌───< 0x004012c9      7370           jae 0x40133b
│    ┌────< 0x004012cb      7265           jb 0x401332
│    ││││   0x004012cd      690043617074   imul eax, dword [eax], 0x74706143
│    ││││   0x004012d3      690000000006   imul eax, dword [eax], 0x6000000
│    ││││   0x004012d9      0000           add byte [eax], al
│    ││││   0x004012db      00ec           add ah, ch
│    ││││   0x004012dd      1d40000100     sbb eax, 0x10040
│    ││││   0x004012e2      0100           add dword [eax], eax
│    ││││   0x004012e4      1c1a           sbb al, 0x1a
│    ││││   0x004012e6      40             inc eax
│    ││││   0x004012e7      0000           add byte [eax], al
│    ││││   0x004012e9      0000           add byte [eax], al
│    ││││   0x004012eb      00ff           add bh, bh
..
│    ││└└─> 0x00401326      88b94847ed26   mov byte [ec
```
  ### 0x00401000
```c
╎╎╎╎   ;-- section..text:
│    ╎╎╎╎   ;-- (0x00401004) _adj_fptan:
┌ 473: sym.imp.MSVBVM60.DLL__CIcos ();
│    ╎╎╎╎   0x00401000  ~   8693a372f909   xchg byte [ebx + 0x9f972a3], dl ; [00] -r-x section size 36864 named .text
│    ╎╎╎╎   0x00401006  ~   a372ee6aa4     mov dword [0xa46aee72], eax ; [0xa46aee72:4]=-1
│    ╎╎╎╎   ;-- __vbaVarMove:
│   ┌─────> 0x00401008      ee             out dx, al
│   ╎╎╎╎╎   0x00401009      6aa4           push 0xffffffffffffffa4
│   ╎╎╎╎╎   ;-- (0x0040100c) __vbaFreeVar:
│  ┌──────< 0x0040100b  ~   7231           jb 0x40103e
│  │╎╎╎╎╎   0x0040100d  ~   68a4722919     push 0x192972a4
│ ┌───────> 0x0040100e      a4             movsb byte es:[edi], byte [esi]
│ ╎│╎╎╎╎╎   0x0040100f  ~   7229           jb 0x40103a
│ ╎│╎╎╎╎╎   ;-- __vbaStrVarMove:
..
│ ╎│╎╎╎╎╎   ;-- (0x00401014) __vbaFreeVarList:
│ ╎│╎╎╎╎╎   0x00401011  ~   19a2726272a4   sbb dword [edx - 0x5b8d9d8e], esp
│ ╎│╎╎╎│╎   ;-- (0x00401018) _adj_fdiv_m64:
│ ╎│╎╎╎└──< 0x00401017  ~   72ba           jb 0x400fd3
│ ╎│╎╎╎ ╎   ;-- (0x0040101c) rtcVarBstrFromChar:
│ ╎│╎╎╎ ╎   0x00401019  ~   02a372c20fa2   add ah, byte [ebx - 0x5df03d8e]
│ ╎│╎╎╎ ╎   ;-- (0x00401020) _adj_fprem1:
│ ╎│╎╎╎┌──> 0x0040101e  ~   a2724109a3     mov byte [0xa3094172], al   ; [0xa3094172:1]=255
│ ╎│╎╎╎╎╎   ;-- (0x00401024) rtcLowerCaseVar:
│ ────────> 0x00401021  ~   09a372a075a2   or dword [ebx - 0x5d8a5f8e], esp
│ ╎│╎╎╎╎╎   0x00401025      75a2           jne 0x400fc9
│ ╎│╎╎╎╎╎   ;-- (0x00401028) rtcTrimBstr:
│ ────────< 0x00401027  ~   7201           jb 0x40102a
│ ╎│╎╎╎╎└─< 0x00401029  ~   76a2           jbe 0x400fcd
│ ────────> 0x0040102a  ~   a27274a2a1     mov byte [0xa1a27472], al   ; [0xa1a27472:1]=255
│ ╎│╎╎╎╎    ;-- (0x0040102c) __vbaHresultCheckObj:
│ ╎│╎╎╎╎┌─< 0x0040102b  ~   7274           jb 0x4010a1
│ ╎│╎╎╎╎│   0x0040102d  ~   a2a172b1c8     mov byte [0xc8b172a1], al   ; [0xc8b172a1:1]=255
│ ╎│╎╎╎╎│   ;-- (0x00401030) rtcIsDate:
│ ╎│╎╎╎╎│   0x0040102e  ~   a172b1c8a1     mov eax, dword [0xa1c8b172] ; [0xa1c8b172:4]=-1
│ ╎│╎╎╎╎│   ;-- (0x00401034) _adj_fdiv_m32:
│ ╎│╎╎╎╎│   0x00401031  ~   c8a1726e       enter 0x72a1, 0x6e
│ ╎│╎╎╎╎│   0x00401035  ~   02a372fec1a1   add ah, byte [ebx - 0x5e3e018e]
│ ╎│╎╎╎╎│   ;-- (0x00401038) __vbaAryDestruct:
│ ────────> 0x00401037  ~   72fe           jb 0x401037
│ ╎│╎╎╎╎│   0x00401039  ~   c1a172f19f..   shl dword [ecx - 0x5e600e8e], 0x72
│ ╎│╎╎╎╎│   ;-- (0x0040103c) __vbaObjSet:
│ ╎│╎╎╎╎│   0x0040103a  ~   a172f19fa1     mov eax, dword [0xa19ff172] ; [0
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 10098/60000 chars across 9 tools -->