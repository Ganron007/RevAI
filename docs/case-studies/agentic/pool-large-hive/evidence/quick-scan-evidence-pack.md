## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=4660766415cdc4a6 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=226, sha256=4660766415cdc4a6ff3bffb20f35c6f3a7ccfd494816b1a135de8c11e7151860
  Anomalies (16): BigBufferNoXrefMediumToHighEntropy×33 (entropy), CrossSectionJump (code), ExecutableSectionNoCode×2 (sections), GuiSubsystemNoWindowApi (headers), HighEntropy (entropy), HugeFunctionGapAtSectionBoundary (code), InvalidBaseOfCode (sections), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), NoChecksum (integrity), Packed (packers), PatchedUPXHeader (packers), PurelyVirtualExecutableSection (sections), SectionNameUnknown (sections), SectionWX×2 (sections), TimeDateStampZero (time)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@220; NoChecksum@216
  YARA (info, 2 total): UPX, upx_39x_lzma_x64
  Functions (1): EntryPoint@4311376
  Top high-signal imports (score≥8, 1 of 4):
    [8] kernel32.VirtualProtect
  Mid-signal imports: kernel32.LoadLibraryA, kernel32.GetProcAddress
  (low-signal/noise imports: 1 omitted)
  Strings/apis (3 total): GetProcAddress, LoadLibraryA, VirtualProtect
  Strings (other, 297 items, omitted)
  Recovered structures (8): MZ, PE, OptionalHeader, Sections, ExceptionTable, ImportTable, kernel32.FT, ImportNames
  Decompilations (1 top functions):
    ### 4311376 (EntryPoint, score=?)
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}
```

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Software Packing'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Software Packing', 'id': 'T1027.002'} (1): packed with UPX
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (1): link function at runtime on Windows
  All rules (1): terminate process

## pe_imports (4 imports, 3 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]

## YARA matches (7)
  Rules: domain, IP, contains_base64, IsPE64, IsWindowsGUI, IsPacked, suspicious_packer_section

## FLOSS strings (7237 total)
  (other strings, 80 items omitted)

<!-- evidence_assembler: used 2236/28000 chars across 5 tools -->