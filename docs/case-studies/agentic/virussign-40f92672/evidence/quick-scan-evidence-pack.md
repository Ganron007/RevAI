## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=353ab6827b750979 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=131, sha256=353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
  Anomalies (16): BigStringHiScore×2 (strings), BssNonEmpty (entropy), CrossSectionJump×232 (code), DataBetweenHeaderAndFirstSection (headers), DelayImports×3 (imports), DynamicString×6 (strings), ExtraSpaceAfterResourcesDataDirectory (resources), HighXrefLoopingFunction×11 (code), HugeGapBetweenFunctions×22 (code), ImportByHash×22 (imports), ManyHighValueImmediates×3 (code), ManyUniqueImmediateBytes×2 (code), NoChecksum (integrity), SequentialFunction×2 (code), SpaghettiFunction×37 (code), XorInLoop×30 (code)
  High-signal anomaly locations: DynamicString@223406,222917,223243; HighXrefLoopingFunction@20932,25412,29988; ManyHighValueImmediates@110848,139808,222680; ManyUniqueImmediateBytes@111056,222680; NoChecksum@344; SequentialFunction@217308,217976; SpaghettiFunction@21156,27772,31340; XorInLoop@23453,23681,109983
  YARA (info, 3 total): TurboLinker, Delphi, ElevatePrivileges
  Functions (15): sub_3cc0d4@46804, sub_3f5d78@217976, sub_3e68f0@155376, sub_3f5adc@217308, sub_471228@722984, sub_463bec@668140, sub_3dfd24@127780, sub_3f7e64@226404, sub_3f7f14@226580, sub_3f7fc4@226756, sub_3eea0c@188428, sub_3f87b8@228792, sub_3f87f8@228856, sub_3f8838@228920, sub_3f8db8@230328
  Top high-signal imports (score≥8, 7 of 153):
    [10] advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW ×2
    [10] kernel32.HeapDestroy
    [10] user32.DestroyWindow
    [8] kernel32.VirtualAlloc ×2
    [8] advapi32.AdjustTokenPrivileges
    [8] advapi32.LookupPrivilegeValueW
    [8] kernel32.VirtualProtect
  Mid-signal imports: advapi32.OpenProcessToken, kernel32.CreateProcessW, kernel32.CreateThread, kernel32.QueryPerformanceCounter, kernel32.GetProcAddress, kernel32.LoadLibraryExW, kernel32.DeleteFileW, kernel32.LoadLibraryA, kernel32.LoadLibraryW, kernel32.GetModuleHandleW, advapi32.RegOpenKeyExW, advapi32.RegQueryValueExW, kernel32.CreateFileW
  (low-signal/noise imports: 133 omitted)
  ⚠ Constants/registry (3): registry::HKEY_CURRENT_USER×6, registry::HKEY_LOCAL_MACHINE×3, registry::HKEY_USERS
  ⚠ Constants/crypto (1): crypto::ChaCha×4
    Constants/guid (2): guid::IUnknown, guid::IDispatch
    Constants/apihash (1): apihash::hash(strstr)
    Constants/hash (2): hash::SHA256, hash::Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640
  Strings/registry (5 total): SOFTWARE\Microso..T\CurrentVersion, Software\Borland\Delphi\Locales, Software\Borland\Locales, Software\Embarcadero\Locales, Software\CodeGear\Locales
  Strings/paths (4 total): D:\Coding\Is\iss..nts\ChaCha20.pas
  Strings/apis (8 total): InitializeConditionVariable, GetFinalPathNameByHandleW, GetCurrentDirectory, InnoSetupLdrWindow, GetDiskFreeSpaceExW, SetDefaultDllDirectories, SetSearchPathMode, GetLongPathNameW
  Strings (other, 283 items, omitted)
  Carved files (6): PNG@875352 (980 bytes), PNG@876332 (3093 bytes), PNG@879428 (6060 bytes), PNG@885488 (9716 bytes), PNG@895204 (28485 bytes), PNG@923692 (88382 bytes)
  Virtual files (24): ICO/100/en-us, ICO/101/en-us, ICO/102/en-us, ICO/103/en-us, ICO/104/en-us, ICO/105/en-us, STR/4085/unk, STR/4086/unk, STR/4087/unk, STR/4088/unk
  Recovered structures (112): MZ, PE, OptionalHeader, Sections, ImportTable, kernel32.OFT, comctl32.OFT, user32.OFT, oleaut32.OFT, advapi32.OFT, kernel32.FT, comctl32.FT, user32.FT, oleaut32.FT, advapi32.FT
  Decompilations (3 top functions):
    ### 46804 (sub_3cc0d4, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3cc0d4(int32_t param_1,undefined4 param_2)

{
    int32_t iVar1;
    undefined4 uVar2;
    int32_t iVar3;
    code **in_FS_OFFSET;
    code *pcStackY_280;
    undefined4 uVar4;
    undefined4 uVar5;
    undefined4 *puVar6;
    code *pcVar7;
    undefined4 uVar8;
    undefined4 uVar9;
    undefined4 uVar10;
    undefined4 *puVar11;
    code *pcStack_250;
    undefined4 uStack_24c;
    code **ppcStack_248;
    code *pcStack_244;
    int16_t *piStack_240;
    code *UNRECOVERED_JUMPTABLE;
    code *pcStack_238;
    undefined4 uStack_234;
    undefined *puStack_230;
    int16_t aiStack_222 [261];
    undefined4 uStack_18;
    code *UNRECOVERED_JUMPTABLE_00;
    int32_t iStack_10;
    undefined4 uStack_c;
    int32_t iStack_8;
    
    uStack_c = 0;
    puStack_230 = 0x3cc0f1;
    iStack_8 = param_1;
    @System@@LStrAddRef$qqrpv(param_1);
    uStack_234 = 0x3cc2fc;
    pcStack_238 = *in_FS_OFFSET;
    *in_FS_OFFSET = &pcStack_238;
    if (iStack_8 == 0) {
        UNRECOVERED_JUMPTABLE = 0x105;
        piStack_240 = aiStack_222;
        pcStack_244 = 0x0;
        ppcStack_248 = 0x3cc118;
        puStack_230 = &stack0xfffffffc;
        jmp_kernel32.GetModuleFileNameW();
    }
    else {
        UNRECOVERED_JUMPTABLE = 0x3cc122;
        puStack_230 = &stack0xfffffffc;
        uVar2 = sub_3c8974(iStack_8);
        UNRECOVERED_JUMPTABLE = 0x3cc134;
        sub_3cb8ec(aiStack_222, 0x105, uVar2);
    }
    if (aiStack_222[0] != 0) {
        iStack_10 = 0;
        ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
        uStack_24c = 0x20019;
        pcStack_250 = 0x0;
        iVar1 = jmp_advapi32.RegOpenKeyExW();
        if (iVar1 != 0) {
            ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
            uStack_24c = 0x20019;
            pcStack_250 = 0x0;
            iVar1 = jmp_advapi32.RegOpenKeyExW();
            if (iVar1 != 0) {
                ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                uStack_24c = 0
```
    ### 217976 (sub_3f5d78, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3f5d78(int32_t param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    uint32_t uVar6;
    uint32_t uVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint32_t uVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint32_t uVar15;
    uint32_t uVar16;
    uint32_t *puVar17;
    uint32_t *puVar18;
    int32_t iVar19;
    int32_t iVar20;
    uint32_t uStack_2f8;
    uint32_t uStack_2f4;
    uint32_t uStack_2f0;
    uint32_t uStack_2ec;
    uint32_t uStack_2e8;
    uint32_t uStack_2e4;
    uint32_t uStack_2e0;
    uint32_t uStack_2dc;
    uint32_t uStack_2d8;
    uint32_t uStack_2d4;
    uint32_t uStack_2d0;
    uint32_t uStack_2cc;
    uint32_t uStack_2c8;
    uint32_t uStack_2c4;
    uint32_t uStack_2c0;
    uint32_t uStack_2bc;
    uint32_t auStack_290 [18];
    uint32_t auStack_248 [10];
    uint32_t auStack_220 [132];
    
    uVar11 = *(param_1 + 0x90);
    uVar8 = *(param_1 + 0x94);
    uVar9 = *(param_1 + 0x98);
    uVar10 = *(param_1 + 0x9c);
    uVar12 = *(param_1 + 0xa0);
    uVar13 = *(param_1 + 0xa4);
    uStack_2e0 = *(param_1 + 0xa8);
    uStack_2dc = *(param_1 + 0xac);
    uVar14 = *(param_1 + 0xb0);
    uVar15 = *(param_1 + 0xb4);
    uVar16 = *(param_1 + 0xb8);
    uVar1 = *(param_1 + 0xbc);
    uVar2 = *(param_1 + 0xc0);
    uVar3 = *(param_1 + 0xc4);
    uStack_2c0 = *(param_1 + 200);
    uStack_2bc = *(param_1 + 0xcc);
    func_0x003c57a0(param_1, auStack_290, 0x80);
    iVar20 = 0x10;
    puVar17 = auStack_290;
    do {
        uVar4 = *puVar17;
        uVar5 = puVar17[1];
        *puVar17 = uVar5 >> 0x18 | uVar5 << 0x18 | uVar5 >> 8 & 0xff00 | (uVar5 & 0xff00) << 8;
        puVar17[1] = uVar4 >> 0x18 | uVar4 << 0x18 | uVar4 >> 8 & 0xff00 | (uVar4 & 0xff00) << 8;
        puVar17 = puVar17 + 2;
        iVar20 = iVar20 + -1;
    } while (iVar20 != 0);
    iVar20 = 0x40;
    puVar17 = 
```
    ### 155376 (sub_3e68f0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3e68f0(undefined4 *param_1,undefined4 param_2,int32_t param_3,undefined4 param_4,int32_t param_5,
               undefined4 param_6)

{
    if (param_3 != 0x20) {
        sub_3c7d10("Assertion failure", "D:\\Coding\\Is\\issrc-build\\Components\\ChaCha20.pas", 0x31);
    }
    if (((param_5 != 0) && (param_5 != 8)) && (param_5 != 0xc)) {
        sub_3c7d10("Assertion failure", "D:\\Coding\\Is\\issrc-build\\Components\\ChaCha20.pas", 0x32);
    }
    *param_1 = 0x61707865;
    param_1[1] = 0x3320646e;
    param_1[2] = 0x79622d32;
    param_1[3] = 0x6b206574;
    sub_3e6820(param_2, param_1 + 4, param_3);
    param_1[0xc] = param_4;
    if (param_5 == 0xc) {
        func_0x003c57a0(param_6, param_1 + 0xd, 0xc);
    }
    else if (param_5 == 8) {
        param_1[0xd] = 0;
        func_0x003c57a0(param_6, param_1 + 0xe, 8);
    }
    else {
        sub_3c5bc4(param_1 + 0xd, 0xc, 0);
    }
    return;
}
```

## capa evidence (44 total, showing top 15)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (4): encode data using XOR, encrypt data using HC-128, encrypt data using RC4 PRGA, encrypt data using Salsa20 or ChaCha
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (3): get common file path, check if file exists, get file size
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (2): get disk information, check OS version
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Execution', 'Command and Scripting Interpreter'], 'tactic': 'Execution', 'technique': 'Command and Scripting Interpreter', 'subtechnique': '', 'id': 'T1059'} (1): accept command line arguments
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  ATT&CK {'parts': ['Discovery', 'System Location Discovery'], 'tactic': 'Discovery', 'technique': 'System Location Discovery', 'subtechnique': '', 'id': 'T1614'} (1): get geographical location
  All rules (2): check for time delay via GetTickCount, hash data with CRC32

## pe_imports (150 imports, 5 high-signal)
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (16)
  Rules: domain, IP, contains_base64, CRC32_poly_Constant, SHA512_Constants, SHA2_BLAKE2_IVs, url, Borland, IsPE32, IsWindowsGUI, Microsoft_Visual_Cpp_v50v60_MFC, disable_dep, escalate_priv, win_registry, win_token, win_files_operation

## FLOSS strings (10018 total)
  apis (6): ImplGetter, InitInstance, GetInterface, GetInterfaceEntry, GetInterfaceTable, GetHashCode
  (other strings, 74 items omitted)

<!-- evidence_assembler: used 11021/28000 chars across 5 tools -->