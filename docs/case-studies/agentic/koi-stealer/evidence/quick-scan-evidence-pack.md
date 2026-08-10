## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=e29d2bd946212328 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=184, sha256=e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
  Anomalies (13): BigStringHiScore×2 (strings), CrossSectionJump×221 (code), DataBetweenHeaderAndFirstSection (headers), DelayImports×3 (imports), HighXrefLoopingFunction×12 (code), HugeFunctionGapAtSectionBoundary (code), HugeGapBetweenFunctions×24 (code), ManyHighValueImmediates (code), ManyUniqueImmediateBytes (code), ResourceDirectoryGap (resources), SequentialFunction×2 (code), SpaghettiFunction×30 (code), XorInLoop×19 (code)
  High-signal anomaly locations: HighXrefLoopingFunction@18868,19588,23820; ManyHighValueImmediates@125716; ManyUniqueImmediateBytes@102136; ResourceDirectoryGap@848464; SequentialFunction@63194,65118; SpaghettiFunction@19744,26152,29624; XorInLoop@21853,22125,101039
  YARA (info, 4 total): TurboLinker, Delphi, InnoInstaller, ElevatePrivileges
  Functions (15): sub_40ab18@40728, sub_4246e4@146148, sub_423164@140644, sub_42ed58@188760, sub_42ee40@188992, sub_4990a4@623780, sub_42114c@132428, sub_432524@203044, sub_41ac0c@106508, sub_41a60c@104972, sub_424717@146199, sub_4056d0@19152, sub_405af8@20216, sub_41c8c4@113860, sub_499977@626039
  Top high-signal imports (score≥8, 7 of 145):
    [10] advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW ×2
    [10] kernel32.HeapDestroy
    [10] user32.DestroyWindow
    [8] kernel32.VirtualAlloc ×2
    [8] advapi32.AdjustTokenPrivileges
    [8] advapi32.LookupPrivilegeValueW
    [8] kernel32.VirtualProtect
  Mid-signal imports: advapi32.OpenProcessToken, kernel32.CreateProcessW, kernel32.CreateThread, kernel32.QueryPerformanceCounter, kernel32.GetProcAddress, kernel32.DeleteFileW, kernel32.LoadLibraryA, kernel32.LoadLibraryExW, kernel32.LoadLibraryW, kernel32.GetModuleHandleW, advapi32.RegOpenKeyExW, advapi32.RegQueryValueExW, kernel32.CreateFileW
  (low-signal/noise imports: 125 omitted)
  - Constants/registry (2): registry::HKEY_LOCAL_MACHINE, registry::HKEY_CURRENT_USER×3
  - Constants/crypto (1): crypto::PKCS_DigestDecoration_SHA256__8_byt_19×2
    Constants/guid (2): guid::IUnknown, guid::IDispatch
    Constants/hash (1): hash::xxhash
    Constants/oid (38): oid::signedData, oid::sha-256, oid::spcIndirectDataContext, oid::spcPEImageData, oid::countryName, oid::organizationName, oid::organizationalUnitName, oid::commonName
  Strings/registry (4 total): Software\Borland\Delphi\Locales, Software\Borland\Locales, Software\Embarcadero\Locales, Software\CodeGear\Locales
  Strings/apis (7 total): InnoSetupLdrWindow, GetLogicalProcessorInformation, GetDiskFreeSpaceExW, SetDefaultDllDirectories, SetSearchPathMode, SetDllDirectoryW, GetLongPathNameW
  Strings (other, 289 items, omitted)
  Carved files (15): DIB@780920 (2664 bytes), DIB@783584 (1640 bytes), DIB@785224 (744 bytes), DIB@785968 (296 bytes), DIB@786264 (5672 bytes), DIB@791936 (3752 bytes), DIB@795688 (2216 bytes), DIB@797904 (1384 bytes), PNG@799288 (4837 bytes), DIB@804128 (16936 bytes)
  Virtual files (30): ICO/1/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, ICO/5/en-us, ICO/6/en-us, ICO/7/en-us, ICO/8/en-us, ICO/9/en-us, ICO/10/en-us
  Recovered structures (134): MZ, PE, OptionalHeader, Sections, ImportTable, kernel32.OFT, comctl32.OFT, version.OFT, user32.OFT, oleaut32.OFT, netapi32.OFT, advapi32.OFT, kernel32.FT, comctl32.FT, version.FT
  Decompilations (3 top functions):
    ### 40728 (sub_40ab18, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40ab18(int32_t param_1,undefined4 param_2)

{
    undefined4 uVar1;
    int32_t iVar2;
    int32_t iVar3;
    undefined4 *in_FS_OFFSET;
    undefined4 uStackY_278;
    undefined4 uVar4;
    undefined4 uVar5;
    undefined4 *puVar6;
    int16_t *piVar7;
    undefined4 uVar8;
    undefined4 uVar9;
    undefined4 uVar10;
    undefined4 *puVar11;
    undefined4 uStack_248;
    undefined4 uStack_244;
    undefined4 *puStack_240;
    undefined4 uStack_23c;
    int16_t *piStack_238;
    code *pcStack_234;
    undefined4 uStack_230;
    undefined4 uStack_22c;
    undefined *puStack_228;
    int16_t aiStack_21e [261];
    undefined4 uStack_14;
    undefined4 uStack_10;
    int32_t iStack_c;
    int32_t iStack_8;
    
    puStack_228 = 0x40ab2f;
    iStack_8 = param_1;
    @System@@LStrAddRef$qqrpv(param_1);
    uStack_22c = 0x40ad3d;
    uStack_230 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_230;
    if (iStack_8 == 0) {
        pcStack_234 = 0x105;
        piStack_238 = aiStack_21e;
        uStack_23c = 0;
        puStack_240 = 0x40ab56;
        puStack_228 = &stack0xfffffffc;
        jmp_kernel32.GetModuleFileNameW();
    }
    else {
        pcStack_234 = 0x40ab60;
        puStack_228 = &stack0xfffffffc;
        uVar1 = sub_4084ec(iStack_8);
        pcStack_234 = 0x40ab72;
        sub_40a34c(aiStack_21e, 0x105, uVar1);
    }
    if (aiStack_21e[0] != 0) {
        iStack_c = 0;
        puStack_240 = &uStack_10;
        uStack_244 = 0xf0019;
        uStack_248 = 0;
        iVar2 = jmp_advapi32.RegOpenKeyExW();
        if (iVar2 != 0) {
            puStack_240 = &uStack_10;
            uStack_244 = 0xf0019;
            uStack_248 = 0;
            iVar2 = jmp_advapi32.RegOpenKeyExW();
            if (iVar2 != 0) {
                puStack_240 = &uStack_10;
                uStack_244 = 0xf0019;
                uStack_248 = 0;
                iVar2 = jmp_advapi32.RegOpenKeyExW();
                if (iVar2 != 0) {
```
    ### 146148 (sub_4246e4, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_4246e4(void)

{
    uint32_t uVar1;
    uint32_t *puVar2;
    int32_t iVar3;
    uint32_t uVar4;
    
    uVar4 = 0;
    puVar2 = 0x4c090c;
    do {
        iVar3 = 8;
        uVar1 = uVar4;
        do {
            if ((uVar1 & 1) == 0) {
                uVar1 = uVar1 >> 1;
            }
            else {
                uVar1 = uVar1 >> 1 ^ 0xedb88320;
            }
            iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
        *puVar2 = uVar1;
        uVar4 = uVar4 + 1;
        puVar2 = puVar2 + 1;
    } while (uVar4 != 0x100);
    return;
}
```
    ### 140644 (sub_423164, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_423164(void)

{
    undefined4 uVar1;
    code *pcVar2;
    int32_t iVar3;
    undefined4 *in_FS_OFFSET;
    undefined4 uVar4;
    undefined4 uVar5;
    undefined4 uStack_24;
    undefined4 uStack_20;
    undefined *puStack_1c;
    undefined4 uStack_14;
    undefined4 uStack_10;
    undefined4 uStack_c;
    undefined4 uStack_8;
    
    puStack_1c = &stack0xfffffffc;
    uStack_14 = 0;
    uStack_8 = 0;
    uStack_20 = 0x42325e;
    uStack_24 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_24;
    uVar5 = "GetUserDefaultUILanguage";
    uVar4 = "kernel32.dll";
    uVar1 = jmp_kernel32.GetModuleHandleW();
    pcVar2 = sub_40e1b8();
    if (pcVar2 == 0x0) {
        iVar3 = sub_41ff44();
        if (iVar3 == 2) {
            iVar3 = sub_423054(0, 0x80000003, ".DEFAULT\\Control Panel\\International", &uStack_c, 1, 0, uVar1, uVar4);
            if (iVar3 == 0) {
                sub_423048(uStack_c, "Locale", &uStack_8);
                jmp_advapi32.RegCloseKey();
            }
        }
        else {
            iVar3 = sub_423054(0, 0x80000001, "Control Panel\\Desktop\\ResourceLocale", &uStack_c, 1, 0, uVar1, uVar4);
            if (iVar3 == 0) {
                sub_423048(uStack_c, 0x423364, &uStack_8);
                jmp_advapi32.RegCloseKey();
            }
        }
        sub_40873c(&uStack_14, 0x423374, uStack_8);
        sub_405920(uStack_14, &uStack_10);
    }
    else {
        (*pcVar2)();
    }
    *in_FS_OFFSET = uVar1;
    sub_407a20(&uStack_14, uVar1, uVar5, sub_423265);
    sub_407a20(&uStack_8);
    return;
}
```

## capa evidence (37 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (4): get common file path, check if file exists, get file size, get file version info
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (2): encode data using XOR, encrypt data using RC4 PRGA
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (2): query environment variable, check OS version
  ATT&CK {'parts': ['Execution', 'Command and Scripting Interpreter'], 'tactic': 'Execution', 'technique': 'Command and Scripting Interpreter', 'subtechnique': '', 'id': 'T1059'} (1): accept command line arguments
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  ATT&CK {'parts': ['Discovery', 'System Location Discovery'], 'tactic': 'Discovery', 'technique': 'System Location Discovery', 'subtechnique': '', 'id': 'T1614'} (1): get geographical location
  All rules (4): check for time delay via GetTickCount, hash data with CRC32, generate random numbers using the Delphi LCG, create directory

## pe_imports (142 imports, 5 high-signal)
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (26)
  Rules: domain, IP, contains_base64, CRC32_poly_Constant, Delphi_CompareCall, url, Borland, IsPE32, IsWindowsGUI, IsPacked, HasOverlay, borland_delphi, Borland_Delphi_40_additional, Microsoft_Visual_Cpp_v50v60_MFC, Borland_Delphi_30_additional, Borland_Delphi_30_, Borland_Delphi_Setup_Module, Borland_Delphi_40, Borland_Delphi_v40_v50, Borland_Delphi_v30, Borland_Delphi_DLL, disable_dep, escalate_priv, win_registry, win_token

## FLOSS strings (11298 total)
  apis (5): ImplGetter, InitInstance, GetInterface, GetInterfaceEntry, GetInterfaceTable
  (other strings, 75 items omitted)

<!-- evidence_assembler: used 10134/28000 chars across 5 tools -->