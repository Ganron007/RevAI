## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=36137a22c973fdb6 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=156, sha256=36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9
  Anomalies (17): DataBetweenHeaderAndFirstSection (headers), ExtraSpaceAfterResourcesDataDirectory (resources), GuiSubsystemNoWindowApi (headers), InvalidBaseOfCode (sections), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), InvalidSizeOfUninitializedData (sections), NoChecksum (integrity), NoImportTable (imports), Packed×2 (packers), PointerToRawDataNotAligned×2 (sections), SectionEmptyName (sections), SectionNameUnknown×3 (sections), SectionWX×3 (sections), SizeOfRawDataNotAligned×2 (sections), UnbalancedVirtualPhysicalRatio (sections), WrongSizeOfOptionalHeader (headers)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@108; NoChecksum@104
  YARA (info, 2 total): upack_037_03, upack_039f_03
  Strings/apis (7 total): LoadLibraryA, OriginalFilename, FileDescription, StringFileInfo, FileVersion, GetProcAddress, VarFileInfo
  Strings (other, 293 items, omitted)
  Carved files (8): DIB@7251 (744 bytes), DIB@7995 (296 bytes), DIB@8291 (3752 bytes), DIB@12043 (2216 bytes), DIB@14259 (1384 bytes), DIB@15643 (9640 bytes), DIB@25283 (4264 bytes), DIB@29547 (1128 bytes)
  Virtual files (11): ICO/1/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, ICO/5/en-us, ICO/6/en-us, ICO/7/en-us, ICO/8/en-us, GRPICO/SC/en-us, VER/1/en-us
  Recovered structures (77): PE, OptionalHeader, Sections, Resources, Resources.ICO, Resources.ICO.1, Resources.ICO.1.en-us, Resources.ICO.2, Resources.ICO.2.en-us, Resources.ICO.3, Resources.ICO.3.en-us, Resources.ICO.4, Resources.ICO.4.en-us, Resources.ICO.5, Resources.ICO.5.en-us

## capa
  incomplete: capa rc=13


## pe_imports (0 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (21)
  Rules: domain, IP, contains_base64, WinUpackv039finalByDwingc2005h1, Upackv039finalDwing, UpackV037Dwing, IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message, WinUpack_v039_final_By_Dwing_c2005_additional, Upack_v0399_Dwing_additional, Upack_V037_V039_Dwing, Upack_v039_final, Upack_v039_final_Sign_by_hot_UNP_additional, WinUpack_v039_final_By_Dwing_c2005_h1, Upack_v039_final_Dwing_h, Upack_v039_final_Sign_by_hot_UNP, Upack_V037_Dwing, WinUpack_v039_final_By_Dwing_c2005_h1_additional, WinUpack_v039_final_By_Dwing_c2005

## FLOSS strings (52 total)
  ips (2): version="5.1.0.0", version="6.0.0.0"
  apis (2): LoadLibraryA, GetProcAddress
  (other strings, 48 items omitted)

<!-- evidence_assembler: used 2496/28000 chars across 5 tools -->