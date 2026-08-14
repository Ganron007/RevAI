## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=9451a7c4f32eb94a | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=7.57, sha256=9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6
  Anomalies (22): BigBufferNoXrefMediumToHighEntropy×3 (entropy), CrossSectionJump (code), DataBetweenHeaderAndFirstSection (headers), DuplicatedSectionName (sections), ExecutableSectionNoCode×2 (sections), ExtraSpaceAfterResourcesDataDirectory (resources), GuiSubsystemNoWindowApi (headers), HugeFunctionGapAtSectionBoundary (code), InvalidBaseOfCode (sections), InvalidBaseOfData (sections), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), NoChecksum (integrity), Packed×6 (packers), PatchedUPXHeader (packers), PurelyVirtualExecutableSection (sections), SectionEmptyName×2 (sections), SectionNameUnknown×2 (sections), SectionWX×2 (sections), UnknownOverlayMediumToHighEntropy (entropy), UnreferencedImports×7 (imports), XorInLoop (code)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@284; NoChecksum@280; XorInLoop@104130
  YARA (info, 7 total): MSVC_6_linker, upx_080_or_higher_01, upx_089_3xx, upx_0896_102_105_122_03, upx_12x, upx_290_lzma_02, upx_391_nrv2e_02
  Functions (1): EntryPoint@104016
  Top high-signal imports (score≥8, 2 of 7):
    [8] kernel32.VirtualAlloc
    [8] kernel32.VirtualProtect
  Mid-signal imports: kernel32.LoadLibraryA, kernel32.GetProcAddress
  (low-signal/noise imports: 3 omitted)
  Strings/paths (1 total): WuC:\WINDOWS\sys
  Strings/apis (8 total): OriginalFilename, FileDescription, StringFileInfo, FileVersion, GetProcAddress, VarFileInfo, LoadLibraryA, VirtualProtect
  Strings (other, 291 items, omitted)
  Carved files (2): DIB@107804 (9640 bytes), DIB@117448 (4264 bytes)
  Virtual files (4): ICO/1/unk, ICO/2/unk, GRPICO/1/unk, VER/1/en-us
  Recovered structures (25): MZ, RichHeader, PE, OptionalHeader, Sections, Resources, Resources.ICO, Resources.ICO.1, Resources.ICO.1.unk, Resources.ICO.2, Resources.ICO.2.unk, Resources.GRPICO, Resources.GRPICO.1, Resources.GRPICO.1.unk, Resources.VER
  Decompilations (1 top functions):
    ### 104016 (EntryPoint, score=?)
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}
```

## capa evidence (1 total, showing top 1)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Software Packing'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Software Packing', 'id': 'T1027.002'} (1): packed with generic packer

## pe_imports (6 imports, 4 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (20)
  Rules: domain, IP, contains_base64, UPXv20MarkusLaszloReiser, UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser, UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser, upx_3, IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasRichSignature, PackerUPX_CompresorGratuito_wwwupxsourceforgenet, UPX_wwwupxsourceforgenet_additional, yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h, Netopsystems_FEAD_Optimizer_1, UPX_290_LZMA, UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser, UPX_290_LZMA_additional, UPX_wwwupxsourceforgenet

## FLOSS strings (470 total)
  paths (1): WuC:\WINDOWS\sys
  (other strings, 79 items omitted)

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: missing — Data Execution Prevention flag not set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 0

<!-- evidence_assembler: used 3904/28000 chars across 7 tools -->