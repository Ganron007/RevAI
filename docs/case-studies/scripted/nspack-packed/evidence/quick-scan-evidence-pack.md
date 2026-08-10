## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=2627682eb7e8180f | packaging=v6.1 -->

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

<!-- evidence_assembler: used 5231/28000 chars across 5 tools -->