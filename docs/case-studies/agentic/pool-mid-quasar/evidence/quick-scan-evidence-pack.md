## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=cde83fd3b872670a | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=146, sha256=cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36
  Anomalies (18): BigBufferNoXrefMediumToHighEntropy×3 (entropy), BigStringHiScore (strings), BssNonEmpty (entropy), CrossSectionJump (code), DynamicString×5 (strings), ExecutableSectionNoCode (sections), ExtraSpaceAfterResourcesDataDirectory (resources), HighXrefLoopingFunction×10 (code), HugeFunctionGapAtSectionBoundary (code), HugeGapBetweenFunctions (code), InvalidSizeOfInitializedData (sections), ManyHighValueImmediates×3 (code), ManyUniqueImmediateBytes (code), SectionWX (sections), SequentialFunction×3 (code), SpaghettiFunction×8 (code), StackArrayInitialisationX64×17 (code), XorInLoop×64 (code)
  High-signal anomaly locations: DynamicString@168598,31297,34209; HighXrefLoopingFunction@82240,190688,787088; ManyHighValueImmediates@79472,80128,1885184; ManyUniqueImmediateBytes@1885184; SequentialFunction@563744,567280,1885184; SpaghettiFunction@3056,45024,50208; XorInLoop@1724,154296,154666
  YARA (signal): CreateService
  YARA (info, 3 total): MinGW, FingerprintSoftware, AutorunKey
  Functions (15): sub_407960@28000, sub_406ef0@25328, sub_407080@25728, sub_407fd0@29648, sub_414500@80128, sub_414270@79472, sub_5cf000@1885184, sub_417a10@93712, sub_43e0b0@251056, sub_43f580@256384, sub_4265a0@154016, sub_4139a0@77216, sub_41f0b0@124080, sub_44113c@263484, sub_442620@268832
  Top high-signal imports (score≥8, 7 of 159):
    [9] advapi32.CreateServiceW ×3
    [9] advapi32.RegCreateKeyW ×2
    [9] advapi32.RegSetValueExW ×2
    [8] advapi32.OpenSCManagerA ×7
    [8] advapi32.StartServiceCtrlDispatcherW ×3
    [8] advapi32.StartServiceA ×2
    [8] kernel32.VirtualProtect ×2
  Mid-signal imports: kernel32.TerminateProcess, kernel32.CreateProcessW, kernel32.QueryPerformanceCounter, kernel32.DeleteFileW, kernel32.GetProcAddress, kernel32.LoadLibraryW, kernel32.CreateFileW, advapi32.RegOpenKeyW
  (low-signal/noise imports: 144 omitted)
  - Constants/registry (1): registry::HKEY_LOCAL_MACHINE×6
    Constants/guid (7): guid::IPersistFile, guid::IShellLinkW, guid::DWebBrowserEvents, guid::IWebBrowserApp, guid::IApplicationAssociationRegistrationUI, guid::IWebBrowser, guid::ITaskbarList3
  Strings/registry (3 total): SOFTWARE\Microso..ersion\Uninstall, SOFTWARE\Microso..rrentVersion\Run, SOFTWARE\Microso..rsion\Uninstall\
  Strings/apis (1 total): CreateServiceW
  Strings (other, 296 items, omitted)
  Carved files (7): DIB@1132040 (1128 bytes), DIB@1133168 (2440 bytes), DIB@1135608 (4264 bytes), DIB@1139872 (9640 bytes), DIB@1149512 (16936 bytes), DIB@1166448 (67624 bytes), PNG@1234072 (74659 bytes)
  Virtual files (9): ICO/1/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, ICO/5/en-us, ICO/6/en-us, ICO/7/en-us, GRPICO/0/en-us, VER/1/en-us
  Recovered structures (56): MZ, PE, OptionalHeader, Sections, TlsDirectory, ExceptionTable, ImportTable, advapi32.OFT, kernel32.OFT, msvcrt.OFT, ole32.OFT, shell32.OFT, advapi32.FT, kernel32.FT, msvcrt.FT
  Decompilations (3 top functions):
    ### 28000 (sub_407960, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_407960(void)

{
    int32_t iVar1;
    undefined4 uVar2;
    int64_t iVar3;
    undefined8 ***pppuVar4;
    uint64_t uVar5;
    undefined8 uVar6;
    undefined *unaff_RBX;
    undefined8 uStack_bc0;
    undefined *puStack_bb8;
    undefined auStack_bb0 [32];
    int64_t iStack_b90;
    int32_t iStack_b88;
    undefined8 ***pppuStack_b78;
    undefined8 uStack_b70;
    undefined *puStack_b68;
    undefined auStack_b60 [8];
    undefined4 uStack_b58;
    undefined8 uStack_b50;
    code *pcStack_b30;
    undefined8 uStack_b28;
    undefined *puStack_b20;
    undefined8 uStack_b18;
    undefined *puStack_b10;
    undefined8 **ppuStack_af8;
    undefined8 uStack_ae8;
    undefined8 uStack_ae0;
    int64_t *piStack_ad8;
    undefined8 ***pppuStack_ad0;
    undefined8 **ppuStack_ac8;
    undefined8 **appuStack_ac0 [2];
    undefined auStack_ab0 [528];
    undefined8 **appuStack_8a0 [66];
    uint64_t uStack_680;
    undefined8 uStack_678;
    undefined8 uStack_660;
    int64_t *piStack_658;
    undefined8 uStack_650;
    undefined auStack_648 [528];
    undefined auStack_438 [528];
    undefined auStack_228 [528];
    
    iVar1 = (*shell32.SHGetSpecialFolderLocation)(0, 0x17);
    if (iVar1 == 0) {
        unaff_RBX = auStack_438;
        (*shell32.SHGetPathFromIDListW)(uStack_660, auStack_648);
        (*shell32.SHGetMalloc)(&piStack_658);
        (**(*piStack_658 + 0x28))(piStack_658, uStack_660);
        (**(*piStack_658 + 0x10))();
        jmp_msvcrt.wcscpy(unaff_RBX, auStack_648);
        uStack_678 = 0x4e804a;
        jmp_msvcrt.wcscat(unaff_RBX);
        uStack_680 = [0x0x511368] + 1;
        if (uStack_680 < 0x3ffffffffffffffd) {
            iVar3 = sub_4e2a60(uStack_680 * 2);
            jmp_msvcrt.wcscpy(iVar3, [0x0x511360]);
            *(iVar3 + [0x0x511368] * 2) = 0;
            jmp_msvcrt.wcscat(unaff_RBX, iVar3);
            jmp_msvcrt.wcscpy(auStack_228, unaff_RBX);
            uStack_
```
    ### 25328 (sub_406ef0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_406ef0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
    int32_t iVar1;
    int64_t *piStack_878;
    int64_t *piStack_870;
    undefined auStack_868 [528];
    undefined auStack_658 [528];
    undefined auStack_448 [528];
    undefined auStack_238 [528];
    
    (*ole32.CoInitialize)(0);
    iVar1 = (*ole32.CoCreateInstance)([0x0x4ed8c0], 0, 1, &IShellLinkW, &piStack_878);
    if (iVar1 < 0) {
        return;
    }
    jmp_msvcrt.wcscpy(auStack_868, param_1);
    jmp_msvcrt.wcscat(auStack_868, "\\native\\dwaglnc.exe");
    (**(*piStack_878 + 0xa0))(piStack_878, auStack_868);
    jmp_msvcrt.wcscpy(auStack_658, param_3);
    (**(*piStack_878 + 0x58))(piStack_878, auStack_658);
    jmp_msvcrt.wcscpy(auStack_448, param_1);
    jmp_msvcrt.wcscat(auStack_448, "\\native");
    (**(*piStack_878 + 0x48))(piStack_878, auStack_448);
    (**(*piStack_878 + 0x88))(piStack_878, 0x511040, 0);
    iVar1 = (***piStack_878)(piStack_878, &IPersistFile, &piStack_870);
    if (-1 < iVar1) {
        jmp_msvcrt.wcscpy(auStack_238, param_2);
        jmp_msvcrt.wcscat(auStack_238, 0x4e804a);
        jmp_msvcrt.wcscat(auStack_238, param_4);
        jmp_msvcrt.wcscat(auStack_238, ".lnk");
        (**(*piStack_870 + 0x30))(piStack_870, auStack_238, 1);
        (**(*piStack_870 + 0x10))();
    }
    (**(*piStack_878 + 0x10))();
    return;
}
```
    ### 25728 (sub_407080, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_407080(undefined8 ***param_1)

{
    int32_t iVar1;
    int64_t iVar2;
    undefined8 ***pppuVar3;
    uint64_t uVar4;
    undefined8 ***pppuStackX_8;
    undefined auStack_708 [32];
    undefined8 ***pppuStack_6e8;
    int32_t iStack_6e0;
    undefined8 ***pppuStack_6d8;
    undefined8 ***pppuStack_6d0;
    undefined *puStack_6c8;
    code *pcStack_6c0;
    undefined auStack_6b8 [8];
    int32_t iStack_6b0;
    undefined8 ***pppuStack_6a8;
    code *pcStack_688;
    undefined8 uStack_680;
    undefined *puStack_678;
    undefined8 uStack_670;
    undefined *puStack_668;
    undefined8 ***pppuStack_650;
    undefined8 uStack_648;
    int64_t *piStack_640;
    undefined8 **appuStack_638 [66];
    undefined8 ***pppuStack_428;
    undefined8 ***pppuStack_420;
    undefined8 ***apppuStack_418 [64];
    undefined8 ***pppuStack_218;
    undefined8 **ppuStack_210;
    undefined8 **appuStack_208 [64];
    
    puStack_678 = &stack0xfffffffffffffff8;
    puStack_668 = auStack_708;
    pcStack_688 = sub_4e3980;
    uStack_680 = 0x5042ac;
    uStack_670 = 0x4078ed;
    puStack_6c8 = auStack_6b8;
    sub_415470(puStack_6c8);
    iStack_6b0 = 0xffffffff;
    iVar1 = (*shell32.SHGetSpecialFolderLocation)(0, 0x17, &uStack_648);
    pppuStack_6d8 = &pppuStack_428;
    if (iVar1 == 0) {
        pppuStack_6d0 = appuStack_638;
        (*shell32.SHGetPathFromIDListW)(uStack_648, pppuStack_6d0);
        (*shell32.SHGetMalloc)(&piStack_640);
        (**(*piStack_640 + 0x28))(piStack_640, uStack_648);
        (**(*piStack_640 + 0x10))();
        jmp_msvcrt.wcscpy(pppuStack_6d8, pppuStack_6d0);
        jmp_msvcrt.wcscat(pppuStack_6d8, 0x4e804a);
        if ([0x0x511368] + 1U < 0x3ffffffffffffffd) {
            pppuStack_6d0 = sub_4e2a60(([0x0x511368] + 1U) * 2);
            jmp_msvcrt.wcscpy(pppuStack_6d0, [0x0x511360]);
            *(pppuStack_6d0 + [0x0x511368] * 2) = 0;
            jmp_msvcrt.wcscat(pppuStack_6d8);

```

## capa evidence (35 total, showing top 15)
  ATT&CK {'parts': ['Persistence', 'Create or Modify System Process', 'Windows Service'], 'tactic': 'Persistence', 'technique': 'Create or Modify System Process', 'subtechnique': 'Windows Service', 'id': 'T1543.003'} (3): create service, stop service, persist via Windows service
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (2): get common file path, check if file exists
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (2): delete registry key, delete registry value
  ATT&CK {'parts': ['Execution', 'System Services', 'Service Execution'], 'tactic': 'Execution', 'technique': 'System Services', 'subtechnique': 'Service Execution', 'id': 'T1569.002'} (2): create service, persist via Windows service
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  ATT&CK {'parts': ['Impact', 'Service Stop'], 'tactic': 'Impact', 'technique': 'Service Stop', 'subtechnique': '', 'id': 'T1489'} (1): stop service
  ATT&CK {'parts': ['Persistence', 'Boot or Logon Autostart Execution', 'Registry Run Keys / Startup Folder'], 'tactic': 'Persistence', 'technique': 'Boot or Logon Autostart Execution', 'subtechnique': 'Registry Run Keys / Startup Folder', 'id': 'T1547.001'} (1): persist via Run registry key
  All rules (5): generate random numbers using a Mersenne Twister, set environment variable, create directory, delete directory, delete file

## pe_imports (159 imports, 6 high-signal)
  create_service (CreateService) [T1543.003]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]

## YARA matches (11)
  Rules: domain, IP, contains_base64, Dropper_Strings, url, IsPE64, IsConsole, Microsoft_Visual_Cpp_80_DLL, create_service, win_registry, win_files_operation

## FLOSS strings (2990 total)
  (other strings, 80 items omitted)

<!-- evidence_assembler: used 11239/28000 chars across 5 tools -->