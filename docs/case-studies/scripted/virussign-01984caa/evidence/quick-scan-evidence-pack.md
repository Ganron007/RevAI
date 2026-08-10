## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=6878836f0ab5bdf0 | packaging=v6.1 -->

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

<!-- evidence_assembler: used 4500/28000 chars across 5 tools -->