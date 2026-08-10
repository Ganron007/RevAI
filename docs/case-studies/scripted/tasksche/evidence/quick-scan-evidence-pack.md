## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=ec3fd41b22989549 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=224, sha256=ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda
  Anomalies (8): BigResourceHighEntropy (resources), CryptoApiUsage (imports), DynamicString (strings), GuiSubsystemNoWindowApi (headers), HighEntropy (entropy), NoChecksum (integrity), SequentialFunction×2 (code), XorInLoop×20 (code)
  High-signal anomaly locations: BigResourceHighEntropy@65776; CryptoApiUsage@6378; DynamicString@26650; GuiSubsystemNoWindowApi@340; NoChecksum@336; SequentialFunction@11902,12732; XorInLoop@11445,11557,11579
  YARA (signal): CreateService
  YARA (info, 7 total): MSVC_6_linker, MSVC_6_rich, Zlib, ValuableFileExtensions, RunShell, msvc_uv_55, msvc_60_07
  Functions (15): sub_402e7e@11902, sub_4031bc@12732, sub_40541f@21535, sub_402a76@10870, sub_40350f@13583, sub_403797@14231, sub_40501f@20511, sub_405535@21813, sub_4010fd@4349, sub_40182c@6188, sub_404c19@19481, sub_403a28@14888, sub_4043b6@17334, sub_405588@21896, sub_4055a3@21923
  Top high-signal imports (score≥8, 8 of 114):
    [10] advapi32.CryptReleaseContext
    [9] advapi32.CreateServiceA ×6
    [9] advapi32.RegCreateKeyW
    [9] advapi32.RegSetValueExA
    [8] advapi32.StartServiceA ×2
    [8] advapi32.OpenSCManagerA
    [8] kernel32.VirtualAlloc
    [8] kernel32.VirtualProtect
  Mid-signal imports: kernel32.CreateProcessA, kernel32.TerminateProcess, kernel32.GetProcAddress, kernel32.LoadLibraryA, kernel32.CreateFileA, kernel32.GetModuleHandleA, advapi32.RegQueryValueExA
  (low-signal/noise imports: 99 omitted)
  ⚠ Constants/registry (2): registry::HKEY_LOCAL_MACHINE, registry::HKEY_CURRENT_USER
  ⚠ Constants/crypto (11): crypto::AES×2, crypto::Rijndael_Te0__0xc66363a5U___32_lil_1024, crypto::Rijndael_Te1__0xa5c66363U___32_lil_1024, crypto::Rijndael_Te2__0x63a5c663U___32_lil_1024, crypto::Rijndael_Te3__0x6363a5c6U___32_lil_1024, crypto::Rijndael_Td0__0x51f4a750U___32_lil_1024, crypto::Rijndael_Td1__0x5051f4a7U___32_lil_1024, crypto::Rijndael_Td2__0xa75051f4U___32_lil_1024, crypto::Rijndael_Td3__0xf4a75051U___32_lil_1024, crypto::Noekeon_Nessie_round__8_byt_17, crypto::crypto_provider
    Constants/compress (4): compress::zinflate_lengthStarts__32_lil_116, compress::zinflate_lengthExtraBits__32_lil_116, compress::zinflate_distanceStarts__32_lil_120, compress::zinflate_distanceExtraBits__32_lil_120
    Constants/hash (1): hash::CRC32
  Strings/registry (1 total): Software\
  Strings/mutex (1 total): Global\MsWinZone..cheCounterMutexA
  Strings/suspicious (1 total): cmd.exe /c "%s"
  Strings/apis (21 total): CreateServiceA, CryptDestroyKey, CryptAcquireContextA, DeleteFileW, CryptDecrypt, CryptEncrypt, CryptImportKey, GetNativeSystemInfo, TaskStart, WriteFile, CloseHandle, CryptGenKey, CreateFileW, MoveFileExW, MoveFileW
  Strings (other, 276 items, omitted)
  Carved files (1): ZIP@26062 (3486039 bytes)
  Virtual files (3): XIA/2058/en-us, VER/1/en-us, MANIF/1/en-us
  Recovered structures (32): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, kernel32.FT, msvcrt.FT, user32.FT, ImportTable, advapi32.OFT, kernel32.OFT, msvcrt.OFT, user32.OFT, ImportNames
  Decompilations (3 top functions):
    ### 11902 (sub_402e7e, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_402e7e(int32_t param_1,uint32_t *param_2,uint8_t *param_3)

{
    int32_t iVar1;
    undefined4 uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    undefined auStack_2c [12];
    int32_t iStack_20;
    uint32_t uStack_18;
    uint32_t uStack_14;
    uint32_t uStack_10;
    uint32_t uStack_c;
    int32_t iStack_8;
    
    iStack_20 = param_1;
    if (*(param_1 + 4) == '\0') {
        (*msvcrt.exception.exception)(0x40f570);
        jmp_msvcrt._CxxThrowException(auStack_2c, 0x40d570);
    }
    uStack_14 = (*param_2 << 0x18 | *(param_2 + 1) << 0x10 | *(param_2 + 2) << 8 | *(param_2 + 3)) ^ *(param_1 + 8);
    uStack_10 = (*(param_2 + 4) << 0x18 | *(param_2 + 5) << 0x10 | *(param_2 + 6) << 8 | *(param_2 + 7)) ^
                *(param_1 + 0xc);
    uVar4 = (*(param_2 + 8) << 0x18 | *(param_2 + 9) << 0x10 | *(param_2 + 10) << 8 | *(param_2 + 0xb)) ^
            *(param_1 + 0x10);
    iVar1 = *(param_1 + 0x410);
    uStack_c = (CONCAT11(*(param_2 + 0xe), *(param_2 + 0xf)) | *(param_2 + 0xc) << 0x18 | *(param_2 + 0xd) << 0x10) ^
               *(param_1 + 0x14);
    if (1 < iVar1) {
        iStack_8 = iVar1 + -1;
        param_2 = param_1 + 0x30;
        uStack_18 = uVar4;
        do {
            uVar5 = *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_c >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_18 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_10 >> 0x18) * 4) ^
                    *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_14 & 0xff) * 4) ^ param_2[-1];
            uVar4 = *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_c >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_18 >> 0x18) * 4) ^
                    *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_14 >> 8 & 0xff) * 4) ^
                    *(&Rijnd
```
    ### 12732 (sub_4031bc, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_4031bc(int32_t param_1,uint8_t *param_2,uint8_t *param_3)

{
    int32_t iVar1;
    undefined4 uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t *puVar5;
    uint32_t uVar6;
    uint32_t uVar7;
    undefined auStack_30 [16];
    int32_t iStack_20;
    uint32_t uStack_14;
    uint32_t uStack_10;
    uint32_t uStack_c;
    int32_t iStack_8;
    
    iStack_20 = param_1;
    if (*(param_1 + 4) == '\0') {
        (*msvcrt.exception.exception)(0x40f570);
        jmp_msvcrt._CxxThrowException(auStack_30, 0x40d570);
    }
    uVar4 = (*param_2 << 0x18 | param_2[1] << 0x10 | param_2[2] << 8 | param_2[3]) ^ *(param_1 + 0x1e8);
    uStack_14 = (param_2[4] << 0x18 | param_2[5] << 0x10 | param_2[6] << 8 | param_2[7]) ^ *(param_1 + 0x1ec);
    uStack_10 = (param_2[8] << 0x18 | param_2[9] << 0x10 | param_2[10] << 8 | param_2[0xb]) ^ *(param_1 + 0x1f0);
    iVar1 = *(param_1 + 0x410);
    uStack_c = (CONCAT11(param_2[0xe], param_2[0xf]) | param_2[0xc] << 0x18 | param_2[0xd] << 0x10) ^ *(param_1 + 500);
    if (1 < iVar1) {
        puVar5 = param_1 + 0x210;
        iStack_8 = iVar1 + -1;
        do {
            uVar7 = *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uStack_c >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uStack_14 >> 0x18) * 4) ^
                    *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uVar4 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uStack_10 & 0xff) * 4) ^ puVar5[-1];
            uVar3 = *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uStack_10 >> 0x18) * 4) ^
                    *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uStack_14 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uVar4 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uStack_c & 0xff) * 4) ^ *puVar5;
            uVar6 = *(&Rijndael_Td0__0x51f4a
```
    ### 21535 (sub_40541f, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

uint32_t sub_40541f(uint32_t param_1,uint8_t *param_2,uint32_t param_3)

{
    uint32_t uVar1;
    uint32_t uVar2;
    
    if (param_2 == 0x0) {
        return 0;
    }
    param_1 = ~param_1;
    if (7 < param_3) {
        uVar2 = param_3 >> 3;
        do {
            param_3 = param_3 - 8;
            uVar1 = *(&CRC32 + (param_1 & 0xff ^ *param_2) * 4) ^ param_1 >> 8;
            uVar1 = *(&CRC32 + (uVar1 & 0xff ^ param_2[1]) * 4) ^ uVar1 >> 8;
            uVar1 = *(&CRC32 + (uVar1 & 0xff ^ param_2[2]) * 4) ^ uVar1 >> 8;
            uVar1 = *(&CRC32 + (uVar1 & 0xff ^ param_2[3]) * 4) ^ uVar1 >> 8;
            uVar1 = *(&CRC32 + (uVar1 & 0xff ^ param_2[4]) * 4) ^ uVar1 >> 8;
            uVar1 = *(&CRC32 + (uVar1 & 0xff ^ param_2[5]) * 4) ^ uVar1 >> 8;
            uVar1 = *(&CRC32 + (uVar1 & 0xff ^ param_2[6]) * 4) ^ uVar1 >> 8;
            param_1 = uVar1 >> 8 ^ *(&CRC32 + (uVar1 & 0xff ^ param_2[7]) * 4);
            param_2 = param_2 + 8;
            uVar2 = uVar2 - 1;
        } while (uVar2 != 0);
    }
    for (; param_3 != 0; param_3 = param_3 - 1) {
        param_1 = param_1 >> 8 ^ *(&CRC32 + (param_1 & 0xff ^ *param_2) * 4);
        param_2 = param_2 + 1;
    }
    return ~param_1;
}
```

## capa evidence (32 total, showing top 15)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (4): encode data using XOR, encrypt data using AES, encrypt data using RC4 KSA, reference AES constants
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (3): get common file path, check if file exists, get file size
  ATT&CK {'parts': ['Persistence', 'Create or Modify System Process', 'Windows Service'], 'tactic': 'Persistence', 'technique': 'Create or Modify System Process', 'subtechnique': 'Windows Service', 'id': 'T1543.003'} (2): create service, persist via Windows service
  ATT&CK {'parts': ['Execution', 'System Services', 'Service Execution'], 'tactic': 'Execution', 'technique': 'System Services', 'subtechnique': 'Service Execution', 'id': 'T1569.002'} (2): create service, persist via Windows service
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Defense Evasion', 'File and Directory Permissions Modification'], 'tactic': 'Defense Evasion', 'technique': 'File and Directory Permissions Modification', 'subtechnique': '', 'id': 'T1222'} (1): set file attributes
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (1): get hostname
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  All rules (2): hash data with CRC32, generate random numbers using the Delphi LCG

## pe_imports (114 imports, 7 high-signal)
  create_service (CreateService) [T1543.003]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (28)
  Rules: domain, IP, contains_base64, Misc_Suspicious_Strings, CRC32_poly_Constant, CRC32_table, RijnDael_AES, RijnDael_AES_CHAR, IsPE32, IsWindowsGUI, IsPacked, HasRichSignature, WannaDecryptor, Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549, ransom_telefonica, Wanna_Cry_Ransomware_Generic, WannaCry_Ransomware, WannaCry_Ransomware_Dropper, wannacry_static_ransom, Microsoft_Visual_Cpp_v60, Microsoft_Visual_Cpp_v50v60_MFC_additional, Microsoft_Visual_Cpp_50, Microsoft_Visual_Cpp_v50v60_MFC, Microsoft_Visual_Cpp, SEH_Init

## FLOSS strings (6240 total)
  registry (1): oftware\
  apis (7): CloseHandle, GetExitCodeProcess, TerminateProcess, WaitForSingleObject, CreateProcessA, GlobalFree, GetProcAddress
  (other strings, 72 items omitted)

<!-- evidence_assembler: used 11733/28000 chars across 5 tools -->