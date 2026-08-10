## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=c5e1c2b5307ebcb3 | packaging=v6.1 -->

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

<!-- evidence_assembler: used 4826/28000 chars across 5 tools -->