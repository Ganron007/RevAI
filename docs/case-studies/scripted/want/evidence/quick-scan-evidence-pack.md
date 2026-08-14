## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=d52f0647e519edce | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=7.94, sha256=d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09
  Anomalies (10): BigBufferNoXrefMediumToHighEntropy×3 (entropy), GuiSubsystemNoWindowApi (headers), HighEntropy (entropy), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), MultiplePackers (packers), Packed (packers), SectionWX×2 (sections), UnbalancedVirtualPhysicalRatio (sections), UnreferencedImports×4 (imports)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@324
  YARA (info, 4 total): MSVC_2017_linker, visual_studio_2017_version_15_0_rich, PECompact2, pecompact_2xx
  Functions (2): EntryPoint@1024, sub_429d8c@168332
  Top high-signal imports (score≥8, 1 of 4):
    [8] kernel32.VirtualAlloc
  Mid-signal imports: kernel32.LoadLibraryA, kernel32.GetProcAddress
  (low-signal/noise imports: 1 omitted)
  Strings/apis (4 total): GetProcAddress, LoadLibraryA, VirtualAlloc, VirtualFree
  Strings (other, 296 items, omitted)
  Recovered structures (9): MZ, RichHeader, PE, OptionalHeader, Sections, kernel32.OFT, ImportTable, ImportNames, Relocations
  Decompilations (2 top functions):
    ### 1024 (EntryPoint, score=?)
```c
EntryPoint {
    // Error while decompiling : not a valid va
}
```
    ### 168332 (sub_429d8c, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_429d8c(int32_t param_1)

{
    undefined *puVar1;
    
    [0x0x429db0] = 0xf0428b11;
    puVar1 = *(param_1 + 0xc);
    *puVar1 = 0xe9;
    *(puVar1 + 1) = 0x429daf - (puVar1 + 5);
    return 0;
}
```

## capa
  incomplete: capa returned empty rules


## pe_imports (4 imports, 3 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (26)
  Rules: domain, contains_base64, PECompactV2XBitsumTechnologies, PECompact2xxBitSumTechnologies, PECompactv2xx, pecompact2, IsPE32, IsWindowsGUI, IsPacked, HasRichSignature, PeCompact_v208_Bitsum_Technologiessignature_by_loveboom, PECompact_2x_Jeremy_Collake, PECompact_20x_Heuristic_Mode_Jeremy_Collake, PECompact_2xx_BitSum_Technologies, PECompact_v2xx, PECompact_V2X_Bitsum_Technologies_additional, PECompact_V2X_Bitsum_Technologies, PECompact_v20_additional, PeCompact_2xx_BitSum_Technologies, PeCompact_253_DLL_BitSum_Technologies_additional, PECompact_v20, PeCompact_253_DLL_BitSum_Technologies, PECompact_v2xx_additional, suspicious_packer_section, SEH_Save

## FLOSS strings (148 total)
  (other strings, 80 items omitted)

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: present — Data Execution Prevention flag set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 0

<!-- evidence_assembler: used 3142/28000 chars across 7 tools -->