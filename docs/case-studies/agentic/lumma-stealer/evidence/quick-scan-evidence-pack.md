## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=706a49b55ba73d12 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=216, sha256=706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50
  Anomalies (12): BigBufferNoXrefMediumToHighEntropy (entropy), HighEntropy (entropy), InvalidSizeOfInitializedData (sections), InvalidSizeOfUninitializedData (sections), ManyHighValueImmediates (code), ManyUniqueImmediateBytes (code), NoChecksum (integrity), RelocSectionNoRelocation (sections), ResourceDirectoryGap (resources), StackArrayInitialisationX86 (code), UnbalancedVirtualPhysicalRatio (sections), XorInLoop×4 (code)
  High-signal anomaly locations: ManyHighValueImmediates@22305; ManyUniqueImmediateBytes@2464; NoChecksum@296; ResourceDirectoryGap@479602; XorInLoop@1497,13355,26614
  YARA (info, 7 total): MSVC_2010_linker, msvs2010_sp1_kb_983509_rich, NsisInstaller, EnumerateProcesses, ElevatePrivileges, RunShell, nsis_overlay_data
  Functions (15): sub_4015a0@2464, sub_406321@22305, sub_405a8c@20108, sub_4073e2@26594, sub_406966@23910, sub_401553@2387, sub_404adc@16092, sub_401186@1414, sub_403ff5@13301, sub_405e00@20992, sub_40145c@2140, sub_4055d9@18905, sub_40650d@22797, EntryPoint@11747, sub_40522d@17965
  Top high-signal imports (score≥8, 4 of 172):
    [10] user32.DestroyWindow ×4
    [10] comctl32.ImageList_Destroy
    [9] advapi32.RegCreateKeyExW
    [9] advapi32.RegSetValueExW
  Mid-signal imports: user32.SendMessageW, kernel32.CreateProcessW, kernel32.CreateThread, kernel32.OpenProcess, user32.SendMessageTimeoutW, kernel32.DeleteFileW, kernel32.GetProcAddress, kernel32.LoadLibraryA, kernel32.LoadLibraryExW, kernel32.LoadLibraryW, advapi32.RegOpenKeyExW, kernel32.CreateFileW, advapi32.RegQueryValueExW, kernel32.GetModuleHandleW, kernel32.GetModuleHandleA
  (low-signal/noise imports: 153 omitted)
  - Constants/registry (3): registry::HKEY_CURRENT_USER×5, registry::HKEY_USERS×2, registry::HKEY_LOCAL_MACHINE×2
  - Constants/crypto (1): crypto::PKCS_DigestDecoration_SHA256__8_byt_19
    Constants/hash (1): hash::xxhash
    Constants/guid (2): guid::IShellLinkW, guid::IPersistFile
    Constants/oid (34): oid::signedData, oid::sha-256, oid::spcIndirectDataContext, oid::spcPEImageData, oid::sha384WithRSAEncryption, oid::countryName, oid::organizationName, oid::organizationalUnitName
  Strings/urls (21 total): Lhttp://cacerts...StampingCA.crt0, Mhttp://crl3.dig..3842021CA1.crl0S, Phttp://cacerts...3842021CA1.crt0, Mhttp://crl4.dig..A3842021CA1.crl0, Ihttp://crl3.dig..eStampingCA.crl0, 7http://cacerts...edIDRootCA.crt0E, 5http://cacerts...stedRootG4.crt0C, 4http://crl3.dig..redIDRootCA.crl0, 4http://crl3.dig..edIDRootCA.crl0, 2http://crl3.dig..ustedRootG4.crl0, 2http://crl3.dig..stedRootG4.crl0, http://ocsp.digicert.com0A, http://ocsp.digicert.com0C, http://ocsp.digicert.com0\, http://ocsp.digicert.com0X
  Strings/registry (8 total): Software\Microso..s\CurrentVersion, HKEY_PERFORMANCE_DATA, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CURRENT_CONFIG, HKEY_CLASSES_ROOT, HKEY_DYN_DATA, HKEY_USERS
  Strings/apis (32 total): ShellExecuteW, HideWindow, EnumProcessModules, GetModuleBaseNameW, EnumProcesses, OpenProcessToken, RegDeleteKeyExW, GetDiskFreeSpaceExW, MoveFileExW, WritePrivateProfileStringW, GetPrivateProfileStringW, CoCreateInstance, SetCurrentDirectoryW, GetFileAttributesW, SetFileAttributesW
  Strings (other, 239 items, omitted)
  Carved files (5): PNG@468464 (11138 bytes), DIB@503672 (9832 bytes), DIB@513504 (4392 bytes), NSIS@523776 (1055469 bytes), PKCS7@1579253 (13639 bytes)
  Virtual files (1): ICO/1/en-us
  Recovered structures (46): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, comctl32.FT, gdi32.FT, kernel32.FT, shell32.FT, user32.FT, version.FT, ole32.FT, ImportTable, advapi32.OFT
  Decompilations (3 top functions):
    ### 2464 (sub_4015a0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

int32_t * sub_4015a0(int32_t **param_1)

{
    uint32_t *puVar1;
    undefined uVar2;
    int16_t iVar3;
    uint32_t uVar4;
    int16_t *piVar5;
    int16_t *piVar6;
    code *pcVar7;
    undefined4 uVar8;
    int32_t iVar9;
    int32_t **ppiVar10;
    int32_t iVar11;
    int32_t *piVar12;
    undefined4 uVar13;
    uint32_t uVar14;
    int32_t iVar15;
    int32_t **ppiVar16;
    undefined *puVar17;
    int32_t **ppiVar18;
    undefined4 uVar19;
    undefined auStack_3b0 [44];
    undefined auStack_384 [548];
    undefined auStack_160 [256];
    int32_t iStack_60;
    undefined4 uStack_5c;
    int32_t iStack_58;
    int32_t iStack_54;
    undefined2 uStack_50;
    int32_t iStack_4c;
    undefined2 uStack_48;
    undefined2 uStack_46;
    undefined2 uStack_44;
    char cStack_3d;
    int32_t iStack_3c;
    uint32_t uStack_38;
    int32_t *apiStack_34 [3];
    int32_t *piStack_28;
    int32_t *piStack_24;
    int32_t *piStack_20;
    int32_t *piStack_1c;
    int32_t *piStack_18;
    int32_t *piStack_14;
    int32_t iStack_10;
    uint32_t uStack_c;
    int32_t *piStack_8;
    
    ppiVar10 = 0x40b0c0;
    pcVar7 = user32.ShowWindow;
    ppiVar16 = param_1;
    ppiVar18 = apiStack_34;
    for (iVar15 = 7; iVar15 != 0; iVar15 = iVar15 + -1) {
        *ppiVar18 = *ppiVar16;
        ppiVar16 = ppiVar16 + 1;
        ppiVar18 = ppiVar18 + 1;
    }
    iVar15 = apiStack_34[1] * 0x4008;
    iStack_10 = [0x0x472dd4];
    ppiVar16 = iVar15 + 0x473000;
    ppiVar18 = apiStack_34[2] * 0x4008 + 0x473000;
    ppiRam0040b0c4 = apiStack_34 + 1;
    piStack_8 = 0x0;
    switch(apiStack_34[0]) {
    case :
        sub_406404("Jump: %d", apiStack_34[1]);
        return apiStack_34[1];
    case :
        uVar13 = sub_40145c(0);
        sub_406404("Aborting: \"%s\"", uVar13);
        uVar13 = 0;
        goto code_r0x0040162d;
    case :
        [0x0x46ad94] = [0x0x46ad94] + 1;
        if ([0x0x472dd4] == 0) {
            return 0x7
```
    ### 22305 (sub_406321, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_406321(int32_t param_1)

{
    undefined4 uVar1;
    
    if (param_1 == -0x80000000) {
        return "HKEY_CLASSES_ROOT";
    }
    if (param_1 == -0x7fffffff) {
        return "HKEY_CURRENT_USER";
    }
    if (param_1 == -0x7ffffffe) {
        return "HKEY_LOCAL_MACHINE";
    }
    if (param_1 == -0x7ffffffd) {
        return "HKEY_USERS";
    }
    if (param_1 == -0x7ffffffc) {
        return "HKEY_PERFORMANCE_DATA";
    }
    if (param_1 == -0x7ffffffb) {
        return "HKEY_CURRENT_CONFIG";
    }
    uVar1 = "HKEY_DYN_DATA";
    if (param_1 != -0x7ffffffa) {
        uVar1 = "invalid registry key";
    }
    return uVar1;
}
```
    ### 20108 (sub_405a8c, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_405a8c(void)

{
    int16_t iVar1;
    code *pcVar2;
    int32_t iVar3;
    undefined2 *puVar4;
    uint32_t uVar5;
    int32_t iVar6;
    undefined4 uVar7;
    uint32_t uVar8;
    undefined4 uStack_58;
    undefined4 uStack_54;
    int32_t iStack_50;
    int32_t iStack_4c;
    int32_t iStack_48;
    uint32_t uStack_44;
    uint32_t uStack_40;
    uint32_t uStack_3c;
    undefined4 uStack_38;
    undefined4 uStack_34;
    uint32_t uStack_30;
    undefined4 uStack_2c;
    
    iVar6 = [0x0x472ddc];
    uStack_2c = 6;
    uStack_30 = 0x405aa0;
    pcVar2 = sub_40645d();
    if (pcVar2 == 0x0) {
        004d30c0 = 0x30;
        uStack_30 = 0;
        uStack_34 = 0x447250;
        uStack_38 = 0;
        004d30c2 = 0x78;
        uStack_3c = "Control Panel\\Desktop\\ResourceLocale";
        uStack_40 = 0x80000001;
        [0x0x4d30c4] = 0;
        uStack_44 = 0x405ae9;
        sub_406034();
        if ([0x0x447250] == 0) {
            uStack_44 = 0;
            iStack_48 = 0x447250;
            iStack_4c = 0x4094d4;
            iStack_50 = ".DEFAULT\\Control Panel\\International";
            uStack_54 = 0x80000003;
            uStack_58 = 0x405b08;
            sub_406034();
        }
        uStack_44 = 0x447250;
        iStack_48 = 0x4d30c0;
        iStack_4c = 0x405b13;
        jmp_kernel32.lstrcatW();
    }
    else {
        uStack_30 = 0x405aa8;
        uStack_30 = (*pcVar2)();
        uStack_30 = uStack_30 & 0xffff;
        uStack_34 = 0x4d30c0;
        uStack_38 = 0x405ab6;
        sub_4060b2();
    }
    uStack_38 = 0x405b18;
    sub_403ff5();
    00472e80 = [0x0x472e28] & 0x20;
    uStack_38 = 0x4c70a8;
    [0x0x472e9c] = 0x10000;
    uStack_3c = 0x405b3a;
    iVar3 = sub_4068df();
    if ((iVar3 == 0) && (*(iVar6 + 0x48) != 0)) {
        uStack_3c = 0;
        uVar8 = 0x462540;
        uStack_40 = 0x462540;
        uStack_44 = [0x0x472df8] + *(iVar6 + 0x4c) * 2;
        iStack_48 = [0x0x472
```

## capa evidence (41 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (6): get common file path, check if file exists, enumerate files on Windows, enumerate files recursively, get file size, get file version info
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (2): query environment variable, get disk size
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (2): query or enumerate registry key, query or enumerate registry value
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  ATT&CK {'parts': ['Collection', 'Input Capture', 'Keylogging'], 'tactic': 'Collection', 'technique': 'Input Capture', 'subtechnique': 'Keylogging', 'id': 'T1056.001'} (1): log keystrokes via polling
  ATT&CK {'parts': ['Execution', 'Command and Scripting Interpreter'], 'tactic': 'Execution', 'technique': 'Command and Scripting Interpreter', 'subtechnique': '', 'id': 'T1059'} (1): accept command line arguments
  ATT&CK {'parts': ['Defense Evasion', 'File and Directory Permissions Modification'], 'tactic': 'Defense Evasion', 'technique': 'File and Directory Permissions Modification', 'subtechnique': '', 'id': 'T1222'} (1): set file attributes
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (1): delete registry key

## pe_imports (171 imports, 5 high-signal)
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  shell_execute (ShellExecute) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (19)
  Rules: domain, IP, contains_base64, CRC32_poly_Constant, url, android_meterpreter, IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDigitalSignature, HasRichSignature, Nullsoft_PiMP_Stub_SFX, escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation

## FLOSS strings (2325 total)
  apis (29): OpenProcessToken, RegDeleteKeyExW, MoveFileExW, GetDiskFreeSpaceExW, GetModuleBaseNameW, EnumProcessModules, EnumProcesses, DeleteFileW, FindFirstFileW, FindNextFileW, FindClose, SetFilePointer
  (other strings, 51 items omitted)

<!-- evidence_assembler: used 11247/28000 chars across 5 tools -->