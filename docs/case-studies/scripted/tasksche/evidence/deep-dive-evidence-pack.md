## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=ec3fd41b22989549 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=224, sha256=ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda
  Anomalies (8): BigResourceHighEntropy (resources), CryptoApiUsage (imports), DynamicString (strings), GuiSubsystemNoWindowApi (headers), HighEntropy (entropy), NoChecksum (integrity), SequentialFunction×2 (code), XorInLoop×20 (code)
  High-signal anomaly locations: BigResourceHighEntropy@65776; CryptoApiUsage@6378; DynamicString@26650; GuiSubsystemNoWindowApi@340; NoChecksum@336; SequentialFunction@11902,12732; XorInLoop@11445,11557,11579
  YARA (signal): CreateService
  YARA (info, 7 total): MSVC_6_linker, MSVC_6_rich, Zlib, ValuableFileExtensions, RunShell, msvc_uv_55, msvc_60_07
  Functions (15): sub_40514d@20813, sub_402e7e@11902, sub_4031bc@12732, sub_40541f@21535, sub_402a76@10870, sub_40350f@13583, sub_403797@14231, sub_40501f@20511, sub_403cfc@15612, sub_405535@21813, sub_4043b6@17334, sub_4010fd@4349, sub_40182c@6188, sub_404c19@19481, sub_403a28@14888
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
    Constants/compress (5): compress::unlzx_table_three__32_lil_64, compress::zinflate_lengthStarts__32_lil_116, compress::zinflate_lengthExtraBits__32_lil_116, compress::zinflate_distanceStarts__32_lil_120, compress::zinflate_distanceExtraBits__32_lil_120
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
    ### 20813 (sub_40514d, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_40514d(int32_t param_1,int32_t param_2,int32_t param_3,int32_t param_4,int32_t param_5,uint8_t **param_6)

{
    uint8_t uVar1;
    uint32_t uVar2;
    uint8_t **ppuVar3;
    int32_t iVar4;
    uint8_t *puVar5;
    uint32_t uVar6;
    int32_t iVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint8_t *puVar12;
    undefined4 uStack_2c;
    uint8_t *puStack_14;
    uint8_t *puStack_10;
    uint8_t *puStack_c;
    uint8_t *puStack_8;
    
    ppuVar3 = param_6;
    puStack_10 = *(param_5 + 0x34);
    uVar9 = *(param_5 + 0x1c);
    puStack_c = *param_6;
    puStack_8 = param_6[1];
    param_6 = *(param_5 + 0x20);
    if (puStack_10 < *(param_5 + 0x30)) {
        puStack_14 = *(param_5 + 0x30) + (-1 - puStack_10);
    }
    else {
        puStack_14 = *(param_5 + 0x2c) - puStack_10;
    }
    uVar8 = *(&unlzx_table_three__32_lil_64 + param_1 * 4);
    uVar2 = *(&unlzx_table_three__32_lil_64 + param_2 * 4);
    do {
        for (; uVar9 < 0x14; uVar9 = uVar9 + 8) {
            puStack_8 = puStack_8 + -1;
            param_6 = param_6 | *puStack_c << (uVar9 & 0x1f);
            puStack_c = puStack_c + 1;
        }
        puVar12 = param_3 + (uVar8 & param_6) * 8;
        uVar1 = *puVar12;
code_r0x004051d5:
        uVar6 = uVar1;
        if (uVar6 != 0) {
            param_6 = param_6 >> (puVar12[1] & 0x1f);
            uVar9 = uVar9 - puVar12[1];
            if ((uVar1 & 0x10) != 0) {
                uVar6 = uVar6 & 0xf;
                uVar10 = *(&unlzx_table_three__32_lil_64 + uVar6 * 4) & param_6;
                param_6 = param_6 >> uVar6;
                uVar10 = uVar10 + *(puVar12 + 4);
                for (uVar9 = uVar9 - uVar6; uVar9 < 0xf; uVar9 = uVar9 + 8) {
                    puStack_8 = puStack_8 + -1;
                    param_6 = param_6 | *puStack_c << (uVar9 & 0x1f);
                    puStack_c = puStack_c + 1;
                }
          
```
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

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 2 functions (asm)
  ### 0x004077ba
```c
┌ 338: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_5ch @ ebp-0x5c
│           ; var int32_t var_60h @ ebp-0x60
│           ; var int32_t var_64h @ ebp-0x64
│           ; var int32_t var_68h @ ebp-0x68
│           ; var int32_t var_6ch @ ebp-0x6c
│           ; var int32_t var_70h @ ebp-0x70
│           ; var int32_t var_74h @ ebp-0x74
│           ; var int32_t var_78h @ ebp-0x78
│           0x004077ba      55             push ebp
│           0x004077bb      8bec           mov ebp, esp
│           0x004077bd      6aff           push 0xffffffffffffffff
│           0x004077bf      6888d44000     push 0x40d488
│           0x004077c4      68f4764000     push 0x4076f4
│           0x004077c9      64a100000000   mov eax, dword fs:[0]
│           0x004077cf      50             push eax
│           0x004077d0      6489250000..   mov dword fs:[0], esp
│           0x004077d7      83ec68         sub esp, 0x68
│           0x004077da      53             push ebx
│           0x004077db      56             push esi
│           0x004077dc      57             push edi
│           0x004077dd      8965e8         mov dword [var_18h], esp
│           0x004077e0      33db           xor ebx, ebx
│           0x004077e2      895dfc         mov dword [var_4h], ebx
│           0x004077e5      6a02           push 2                      ; 2
│           0x004077e7      ff15c4814000   call dword [sym.imp.MSVCRT.dll___set_app_type] ; 0x4081c4 ; "2\xdf"
│           0x004077ed      59             pop ecx
│           0x004077ee      830d4cf940..   or dword [0x40f94c], 0xffffffff ; [0x40f94c:4]=0
│           0x004077f5      830d50f940..   or dword [0x40f950], 0xffffffff ; [0x40f950:4]=0
│           0x004077fc      ff15c0814000   call dword [sym.imp.MSVCRT.dll___p__fmode] ; 0x4081c0 ; "$\xdf"
│           0x00407802      8b0d48f94000   mov ecx, dword [0x40f948]   ; [0x40f948:4]=0
│           0x00407808      8908           mov dword [eax], ecx
│           0x0040780a      ff15bc814000   call dword [sym.imp.MSVCRT.dll___p__commode] ; 0x4081bc
│           0x00407810      8b0d44f94000   mov ecx, dword [0x40f944]   ; [0x40f944:4]=0
│           0x00407816      8908           mov dword [eax], ecx
│           0x00407818      a1b8814000     mov eax, dword [sym.imp.MSVCRT.dll__adjust_fdiv] ;
```
  ### 0x00401fe7
```c
; CALL XREF from entry0 @ 0x4078e9(x)
┌ 391: int main (int argc, char **argv, char **envp);
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_20bh @ ebp-0x20b
│           ; var int32_t var_20ch @ ebp-0x20c
│           ; var int32_t var_6e4h @ ebp-0x6e4
│           0x00401fe7      55             push ebp
│           0x00401fe8      8bec           mov ebp, esp
│           0x00401fea      81ece4060000   sub esp, 0x6e4
│           0x00401ff0      a010f94000     mov al, byte [0x40f910]     ; [0x40f910:1]=0
│           0x00401ff5      53             push ebx
│           0x00401ff6      56             push esi
│           0x00401ff7      57             push edi
│           0x00401ff8      8885f4fdffff   mov byte [var_20ch], al
│           0x00401ffe      b981000000     mov ecx, 0x81               ; 129
│           0x00402003      33c0           xor eax, eax
│           0x00402005      8dbdf5fdffff   lea edi, [var_20bh]
│           0x0040200b      f3ab           rep stosd dword es:[edi], eax
│           0x0040200d      66ab           stosw word es:[edi], ax
│           0x0040200f      aa             stosb byte es:[edi], al
│           0x00402010      8d85f4fdffff   lea eax, [var_20ch]
│           0x00402016      6808020000     push 0x208                  ; 520
│           0x0040201b      33db           xor ebx, ebx
│           0x0040201d      50             push eax
│           0x0040201e      53             push ebx
│           0x0040201f      ff158c804000   call dword [sym.imp.KERNEL32.dll_GetModuleFileNameA] ; 0x40808c ; DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
│           0x00402025      68acf84000     push 0x40f8ac
│           0x0040202a      e8f6f1ffff     call 0x401225
│           0x0040202f      59             pop ecx
│           0x00402030      ff156c814000   call dword [sym.imp.MSVCRT.dll___p___argc] ; 0x40816c
│           0x00402036      833802         cmp dword [eax], 2
│       ┌─< 0x00402039      7553           jne 0x40208e
│       │   0x0040203b      6838f54000     push 0x40f538               ; "/i"
│       │   0x00402040      ff1568814000   call dword [sym.imp.MSVCRT.dll___p___argv] ; 0x408168
│       │   0x00402046      8b00           mov eax, dword [eax]
│       │   0x00402048      ff7004         push dword [eax + 4]
│       │   0x0040204b      e8f0560000     call 0x407740
│       │   0x00402050      59             pop ecx
│       │   0x00402051      85c0           test eax, eax
│       │   0x
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 17776/60000 chars across 9 tools -->