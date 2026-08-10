## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=91b176fb0d650dcc | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=195, sha256=91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc
  Anomalies (16): BigBufferNoXrefMediumToHighEntropy (entropy), DataBetweenHeaderAndFirstSection (headers), ExecutableSectionNoCode×2 (sections), GuiSubsystemNoWindowApi (headers), HugeFunctionGapAtSectionBoundary (code), InvalidBaseOfCode (sections), InvalidBaseOfData (sections), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), NoChecksum (integrity), Packed×7 (packers), SectionNameUnknown (sections), SectionWX×2 (sections), UnknownOverlayMediumToHighEntropy (entropy), UnreferencedImports×10 (imports), XorInLoop (code)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@332; NoChecksum@328; XorInLoop@189059
  YARA (info, 9 total): MSVC_6_linker, MSVC_6_rich, upx_080_or_higher_01, upx_089_3xx, upx_0896_102_105_122_03, upx_12x, upx_290_lzma_02, upx_391_nrv2b_01, upx_394_nrv2b_01
  Functions (1): EntryPoint@188976
  Top high-signal imports (score≥8, 2 of 10):
    [8] kernel32.VirtualAlloc
    [8] kernel32.VirtualProtect
  Mid-signal imports: kernel32.LoadLibraryA, kernel32.GetProcAddress
  (low-signal/noise imports: 6 omitted)
  Strings/apis (3 total): GetProcAddress, LoadLibraryA, VirtualProtect
  Strings (other, 297 items, omitted)
  Recovered structures (13): MZ, RichHeader, PE, OptionalHeader, Sections, UPX.PackHeader, ImportTable, kernel32.FT, msvcrt.FT, oleaut32.FT, user32.FT, ws2_32.FT, ImportNames
  Decompilations (1 top functions):
    ### 188976 (EntryPoint, score=?)
```c
/* WARNING: Instruction at (ram,0x0042e338) overlaps instruction at (ram,0x0042e337)
    */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    char cVar1;
    undefined uVar2;
    char cVar3;
    int32_t iVar4;
    code *pcVar5;
    uint8_t uVar6;
    undefined *puVar7;
    int32_t iVar8;
    int32_t iVar9;
    uint32_t uVar10;
    undefined4 uVar11;
    uint8_t *puVar12;
    int32_t iVar13;
    int32_t **ppiVar14;
    undefined4 *puVar15;
    uint32_t uVar16;
    uint32_t uVar17;
    int32_t *piVar18;
    uint32_t uVar19;
    uint32_t *puVar20;
    undefined4 *puVar21;
    int32_t **ppiVar22;
    int32_t **ppiVar23;
    int32_t **ppiVar24;
    bool bVar25;
    bool bVar26;
    bool bVar27;
    undefined auStack_a0 [88];
    undefined4 uStack_48;
    int32_t iStack_44;
    undefined4 uStack_40;
    int32_t iStack_3c;
    int32_t *piStack_38;
    int32_t iStack_34;
    int32_t iStack_30;
    int32_t iStack_2c;
    int32_t ***pppiStack_28;
    int32_t **ppiStack_24;
    
    puVar20 = 0x42b000;
    puVar21 = 0x401000;
    uVar19 = 0xffffffff;
    do {
        uVar16 = *puVar20;
        bVar25 = puVar20 < 0xfffffffc;
        puVar20 = puVar20 + 1;
        bVar26 = CARRY4(uVar16, uVar16) || CARRY4(uVar16 * 2, bVar25);
        uVar16 = uVar16 * 2 + bVar25;
        do {
            if (bVar26) {
                uVar2 = *puVar20;
                puVar20 = puVar20 + 1;
                *puVar21 = uVar2;
                puVar21 = puVar21 + 1;
            }
            else {
                uVar10 = 1;
                do {
                    do {
                        bVar25 = CARRY4(uVar16, uVar16);
                        uVar17 = uVar16 * 2;
                        if (uVar17 == 0) {
                            uVar16 = *puVar20;
                            bVar26 = puVar20 < 0xfffffffc;
                            puVar20 = puVar20 + 1;
                            bVar25 = CARRY4(uVar16, uVar16) || CARRY4(uVar16 * 2, bVar26);
       
```

## capa evidence (1 total, showing top 1)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Software Packing'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Software Packing', 'id': 'T1027.002'} (1): packed with UPX

## pe_imports (10 imports, 4 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (25)
  Rules: domain, IP, contains_base64, VirtualPC_Detection, UPX, UPXv20MarkusLaszloReiser, UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser, UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser, upx_3, IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasRichSignature, PackerUPX_CompresorGratuito_wwwupxsourceforgenet, UPX_wwwupxsourceforgenet_additional, yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h, Netopsystems_FEAD_Optimizer_1, UPX_290_LZMA, UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser, UPX_290_LZMA_additional, UPX_wwwupxsourceforgenet, suspicious_packer_section, vmdetect, Str_Win32_Winsock2_Library

## FLOSS strings (2050 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm))
  (no disassembly)


## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 4991/60000 chars across 9 tools -->