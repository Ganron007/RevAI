## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=62a5c9c2f17d2ae5 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=112, sha256=62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb
  Anomalies (20): BigStringHiScore×9 (strings), EmbeddedProgram×10 (embedding), EntryPointInNonExecRegion (code), GuiSubsystemNoWindowApi (headers), InvalidBaseOfCode (sections), InvalidBaseOfData (sections), InvalidChecksum (integrity), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), MultiplePackers×4 (packers), Packed×6 (packers), PossiblePackerApiDynamicImport×3 (imports), RelocSectionNoRelocation (sections), RelocationsNotInRelocSection (sections), ResourceDirectoryGap (resources), SectionNameUnknown×2 (sections), SectionWeirdRights (sections), StackArrayInitialisationX86 (code), UnreferencedImports×4 (imports), UnsignedMicrosoft×5 (integrity)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@276; ResourceDirectoryGap@26344
  YARA (signal): AccessNetworkShares
  YARA (info, 11 total): MSVC_6_linker, Aspack_sections, ZoneAlternateStream, FingerprintEnvironment, EnumerateProcesses, ValuableFileExtensions, ElevatePrivileges, RunShell, aspack_uv_10, aspack_asprotect_2xx…
  Functions (2): EntryPoint@34305, sub_40900a@34314
  Mid-signal imports: kernel32.GetProcAddress, kernel32.LoadLibraryA, kernel32.GetModuleHandleA
  (low-signal/noise imports: 1 omitted)
  ⚠ Constants/crypto (2): crypto::rfc3548_Base_32_Encoding__8_byt_ASC_32×2, crypto::PKCS_DigestDecoration_SHA256__8_byt_19×40
    Constants/compress (2): compress::Zlib_base_length__8_byt_29, compress::unlzx_table_one__8_byt_32
    Constants/oid (46): oid::signedData, oid::sha-256, oid::spcIndirectDataContext, oid::spcPEImageData, oid::stateOrProvinceName, oid::localityName, oid::organizationName, oid::commonName
    Constants/guid (24): guid::IShellLinkW, guid::IPersistFile, guid::ITaskbarList3, guid::IShellFolder, guid::IUnknown, guid::IDataObject, guid::IEnumFORMATETC, guid::IDropTarget
  Strings/urls (70 total): http://www.7-zip.org/, https://go.micro..k/?linkid=798306, https://aka.ms/d..-core-applaunch?, Mhttp://crl4.dig..3842021CA1.crl0>, Lhttp://cacerts...StampingCA.crt0, Phttp://cacerts...3842021CA1.crt0, Ihttp://crl.micr..2011_03_22.crl0^, Mhttp://crl3.dig..3842021CA1.crl0S, Nhttp://www.micr..%202010(1).crl0l, Phttp://www.micr..A%202010(1).crt0, Ehttp://crl.micr..2010-06-23.crl0Z, Chttp://www.micr..2011-10-19.crl0a
  Strings/registry (24 total): Software\7-zip, Software\Microso..ensions\Approved, Software\Policie..\ClientTelemetry, Software\Microso..\Uninstall\7-Zip, Software\Microso..p Paths\7zFM.exe, Software\Microso..ersistentOrapiUT, Software\Policie..oft\cloud\Office, Software\Policie..oft\Cloud\Office, Software\Policie..crosoft\Security, Software\AppData..Microsoft\Office, Software\Policie..Microsoft\Office, Software\Policie..\Microsoft\Cloud
  Strings/paths (4 total): C:\Program Files..GoogleUpdate.exe, D:\a\_work\1\s\a..otnet\dotnet.pdb
  Strings/apis (7 total): ShellExecuteW, GetUserNameW, GetSystemInfo, GetVersionExW
  Strings (other, 195 items, omitted)
  Carved files (48): DIB@39296 (3696 bytes), PE@92825 (17696 bytes), PE@125121 (650240 bytes), PKCS7@783385 (10384 bytes), PKCS7@807600 (10322 bytes), PE@817927 (14848 bytes), DIB@845190 (744 bytes), DIB@845934 (296 bytes), PE@848133 (24160 bytes), PKCS7@886124 (10322 bytes)
  Virtual files (3): ICO/30001/unk, GRPICO/1/unk, VER/1/zh-cn
  Recovered structures (25): MZ, RichHeader, PE, OptionalHeader, Sections, Resources, Resources.VER, Resources.GRPICO, Resources.ICO, Resources.VER.1, Resources.GRPICO.1, Resources.ICO.30001, Resources.VER.1.zh-cn, Resources.GRPICO.1.unk, Resources.ICO.30001.unk
  Decompilations (2 top functions):
    ### 34305 (EntryPoint, score=?)
```c
EntryPoint {
    // Error while decompiling : not a valid va
}
```
    ### 34314 (sub_40900a, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40900a(void)

{
    return;
}
```

## capa evidence (4 total, showing top 4)
  ATT&CK {'parts': ['Defense Evasion', 'Virtualization/Sandbox Evasion', 'System Checks'], 'tactic': 'Defense Evasion', 'technique': 'Virtualization/Sandbox Evasion', 'subtechnique': 'System Checks', 'id': 'T1497.001'} (1): reference anti-VM strings targeting VirtualBox
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Software Packing'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Software Packing', 'id': 'T1027.002'} (1): packed with ASPack
  All rules (2): contain an embedded PE file, contains PDB path

## pe_imports (4 imports, 2 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (35)
  Rules: domain, IP, contains_base64, Antivirus, Misc_Suspicious_Strings, Big_Numbers1, CRC32_poly_Constant, url, ASPackv212AlexeySolodovnikov, ASProtectV2XDLLAlexeySolodovnikov, IsPE32, IsWindowsGUI, HasOverlay, HasRichSignature, ASPack_v212_additional, ASPack_v21_additional, ASProtect_V2X_DLL_Alexey_Solodovnikov, ASPack_v212, yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h, ASPack_v211d, ASProtect_V2X_DLL_Alexey_Solodovnikov_additional, ASPack_212withouth_Poly_Solodovnikov_Alexey, ASPack_v212_Alexey_Solodovnikov, suspicious_packer_section, DebuggerException__SetConsoleCtrl

## FLOSS strings (13079 total)
  urls (1): http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.
  apis (6): VirtualAlloc, VirtualFree, ExitProcess, GetProcAddress, GetModuleHandleA, LoadLibraryA
  (other strings, 73 items omitted)

<!-- evidence_assembler: used 5556/28000 chars across 5 tools -->