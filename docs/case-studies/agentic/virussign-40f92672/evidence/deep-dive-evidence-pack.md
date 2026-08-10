## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=353ab6827b750979 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=131, sha256=353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
  Anomalies (16): BigStringHiScore×2 (strings), BssNonEmpty (entropy), CrossSectionJump×232 (code), DataBetweenHeaderAndFirstSection (headers), DelayImports×3 (imports), DynamicString×6 (strings), ExtraSpaceAfterResourcesDataDirectory (resources), HighXrefLoopingFunction×11 (code), HugeGapBetweenFunctions×22 (code), ImportByHash×23 (imports), ManyHighValueImmediates×3 (code), ManyUniqueImmediateBytes×2 (code), NoChecksum (integrity), SequentialFunction×2 (code), SpaghettiFunction×37 (code), XorInLoop×30 (code)
  High-signal anomaly locations: DynamicString@223406,222917,223243; HighXrefLoopingFunction@20932,25412,29988; ManyHighValueImmediates@110848,139808,222680; ManyUniqueImmediateBytes@111056,222680; NoChecksum@344; SequentialFunction@217308,217976; SpaghettiFunction@21156,27772,31340; XorInLoop@23453,23681,109983
  YARA (info, 3 total): TurboLinker, Delphi, ElevatePrivileges
  Functions (15): sub_3cc0d4@46804, sub_3f5d78@217976, sub_3f5adc@217308, sub_3e68f0@155376, sub_466d8c@680844, sub_471228@722984, sub_463bec@668140, sub_3dfd24@127780, sub_3f7e64@226404, sub_3f7f14@226580, sub_3f7fc4@226756, sub_3eea0c@188428, sub_3f87b8@228792, sub_3f87f8@228856, sub_3f8838@228920
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
  ⚠ Constants/registry (3): registry::HKEY_LOCAL_MACHINE×3, registry::HKEY_CURRENT_USER×5, registry::HKEY_USERS
  ⚠ Constants/crypto (1): crypto::ChaCha×3
    Constants/guid (2): guid::IUnknown, guid::IDispatch
    Constants/apihash (1): apihash::hash(strstr)
    Constants/hash (3): hash::xxhash, hash::SHA256, hash::Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640
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
    ### 217308 (sub_3f5adc, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3f5adc(int32_t param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t *puVar4;
    int32_t *piVar5;
    int32_t iVar6;
    uint32_t uVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    int32_t iVar11;
    uint32_t uStack_13c;
    uint32_t uStack_138;
    uint32_t uStack_134;
    uint32_t uStack_130;
    uint32_t uStack_12c;
    uint32_t uStack_128;
    uint32_t *puStack_114;
    uint32_t auStack_110 [9];
    uint32_t auStack_ec [5];
    uint32_t auStack_d8 [50];
    
    uVar8 = *(param_1 + 0x90);
    uVar7 = *(param_1 + 0x94);
    uVar1 = *(param_1 + 0x98);
    uStack_134 = *(param_1 + 0x9c);
    uVar10 = *(param_1 + 0xa0);
    uVar9 = *(param_1 + 0xa4);
    uVar2 = *(param_1 + 0xa8);
    uStack_128 = *(param_1 + 0xac);
    func_0x003c57a0(param_1, auStack_110, 0x40);
    iVar6 = 0x10;
    puVar4 = auStack_110;
    do {
        uVar3 = *puVar4;
        *puVar4 = uVar3 >> 0x18 | uVar3 << 0x18 | uVar3 >> 8 & 0xff00 | (uVar3 & 0xff00) << 8;
        puVar4 = puVar4 + 1;
        iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    iVar6 = 0x30;
    puVar4 = auStack_110;
    do {
        puVar4 = puVar4 + 1;
        uVar3 = puVar4[0xd];
        puVar4[0xf] = ((uVar3 << 0xf | uVar3 >> 0x11) ^ (uVar3 << 0xd | uVar3 >> 0x13) ^ puVar4[0xd] >> 10) +
                      puVar4[-1] +
                      ((*puVar4 << 0x19 | *puVar4 >> 7) ^ (*puVar4 << 0xe | *puVar4 >> 0x12) ^ *puVar4 >> 3) + puVar4[8]
        ;
        iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    iVar6 = 0x40;
    piVar5 = &SHA256;
    puStack_114 = auStack_110;
    do {
        uStack_12c = uVar2;
        uStack_130 = uVar9;
        uStack_138 = uVar1;
        uStack_13c = uVar7;
        uVar9 = uVar10;
        uVar7 = uVar8;
        iVar11 = (uVar9 & uStack_130 ^ ~uVar9 & uStack_12c) +
                 ((uVar9 << 0x1a | uVar9 >> 6) ^ (uVar9 << 0x15 | uVar9 >> 0xb) ^ (uVar9 << 7 | uVar9 >> 0x
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

## FLOSS strings (10027 total)
  apis (2): ImplGetter, InitInstance
  (other strings, 78 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 4 functions (asm)
  ### 0x00471e60
```c
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_40h @ ebp-0x40
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf                ; 15
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           0x00471e80      68c6264700     push 0x4726c6
│           0x00471e85      64ff30         push dword fs:[eax]
│           0x00471e88      648920         mov dword fs:[eax], esp
│           0x00471e8b      33d2           xor edx, edx
│           0x00471e8d      55             push ebp
│           0x00471e8e      6880264700     push 0x472680
│           0x00471e93      64ff32         push dword fs:[edx]
│           0x00471e96      648922         mov dword fs:[edx], esp
│           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000
│           0x00471e9e      e81583ffff     call 0x46a1b8
│           0x00471ea3      33c0           xor eax, eax
│           0x00471ea5      8945ec         mov dword [var_14h], eax
│           0x00471ea8      33d2           xor edx, edx
│           0x00471eaa      55             push ebp
│           0x00471eab      686f264700     push 0x47266f               ; 'o&G'
│           0x00471eb0      64ff32         push dword fs:[edx]
│           0x00471eb3      648922         mov dword fs:[edx], esp
│           0x00471eb6      8d55ec         lea edx, [var_14h]
│           0x00471eb9      33c0           xor eax, eax
│           0x00471ebb      e87c14ffff     call 0x46333c
│           0x00471ec0      8d45ec         lea eax, [var_14h]
│           0x00471ec3      e8a47cffff     call 0x469b6c
│           0x00471ec8      6a02           push 2                      ; 2
│           0x00471eca      6a00           push 0
│           0x00471ecc      
```
  ### 0x003ce578
```c
┌ 167: sym.SetupLdr.e32___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x003ce578      55             push ebp
│       ╎   0x003ce579      8bec           mov ebp, esp
│       ╎   0x003ce57b      51             push ecx
│       ╎   0x003ce57c      53             push ebx
│       ╎   0x003ce57d      56             push esi
│       ╎   0x003ce57e      57             push edi
│       ╎   0x003ce57f      33c0           xor eax, eax
│       ╎   0x003ce581      8945fc         mov dword [var_4h], eax
│       ╎   0x003ce584      33c0           xor eax, eax
│       ╎   0x003ce586      55             push ebp
│       ╎   0x003ce587      6819e63c00     push 0x3ce619
│       ╎   0x003ce58c      64ff30         push dword fs:[eax]
│       ╎   0x003ce58f      648920         mov dword fs:[eax], esp
│       ╎   0x003ce592      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce595      50             push eax
│       ╎   0x003ce596      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce599      50             push eax
│       ╎   0x003ce59a      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce59d      50             push eax
│       ╎   0x003ce59e      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a1      50             push eax
│       ╎   0x003ce5a2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a5      50             push eax
│       ╎   0x003ce5a6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a9      50             push eax
│       ╎   0x003ce5aa      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5ad      50             push eax
│       ╎   0x003ce5ae      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b1      50             push eax
│       ╎   0x003ce5b2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b5      50             push eax
│       ╎   0x003ce5b6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b9      50             push eax
│       ╎   0x003ce5ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5bd      50             push eax
│       ╎   0x003ce5be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c1      50             push eax
│       ╎   0x003ce5c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c5      50             push eax
│       ╎   0x003ce5c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c9      50             push eax
│       ╎
```
  ### 0x003ce188
```c
; CALL XREF from sym.SetupLdr.e32___dbk_fcall_wrapper @ 0x3ce607(x)
┌ 1007: fcn.003ce188 ();
│           0x003ce188      55             push ebp
│           0x003ce189      8bec           mov ebp, esp
│           0x003ce18b      e8f4ffffff     call fcn.003ce184
│           0x003ce190      e8efffffff     call fcn.003ce184
│           0x003ce195      e8eaffffff     call fcn.003ce184
│           0x003ce19a      e8e5ffffff     call fcn.003ce184
│           0x003ce19f      e8e0ffffff     call fcn.003ce184
│           0x003ce1a4      e8dbffffff     call fcn.003ce184
│           0x003ce1a9      e8d6ffffff     call fcn.003ce184
│           0x003ce1ae      e8d1ffffff     call fcn.003ce184
│           0x003ce1b3      e8ccffffff     call fcn.003ce184
│           0x003ce1b8      e8c7ffffff     call fcn.003ce184
│           0x003ce1bd      e8c2ffffff     call fcn.003ce184
│           0x003ce1c2      e8bdffffff     call fcn.003ce184
│           0x003ce1c7      e8b8ffffff     call fcn.003ce184
│           0x003ce1cc      e8b3ffffff     call fcn.003ce184
│           0x003ce1d1      e8aeffffff     call fcn.003ce184
│           0x003ce1d6      e8a9ffffff     call fcn.003ce184
│           0x003ce1db      e8a4ffffff     call fcn.003ce184
│           0x003ce1e0      e89fffffff     call fcn.003ce184
│           0x003ce1e5      e89affffff     call fcn.003ce184
│           0x003ce1ea      e895ffffff     call fcn.003ce184
│           0x003ce1ef      e890ffffff     call fcn.003ce184
│           0x003ce1f4      e88bffffff     call fcn.003ce184
│           0x003ce1f9      e886ffffff     call fcn.003ce184
│           0x003ce1fe      e881ffffff     call fcn.003ce184
│           0x003ce203      e87cffffff     call fcn.003ce184
│           0x003ce208      e877ffffff     call fcn.003ce184
│           0x003ce20d      e872ffffff     call fcn.003ce184
│           0x003ce212      e86dffffff     call fcn.003ce184
│           0x003ce217      e868ffffff     call fcn.003ce184
│           0x003ce21c      e863ffffff     call fcn.003ce184
│           0x003ce221      e85effffff     call fcn.003ce184
│           0x003ce226      e859ffffff     call fcn.003ce184
│           0x003ce22b      e854ffffff     call fcn.003ce184
│           0x003ce230      e84fffffff     call fcn.003ce184
│           0x003ce235      e84affffff     call fcn.003ce184
│           0x003ce23a      e845ffffff     call fcn.003ce184
│           0x003ce23f      e840ffffff     call fcn.003ce184
│           0x003ce244      e83bffffff    
```
  ### 0x003ce184
```c
; XREFS(200)
┌ 1: fcn.003ce184 ();
└           0x003ce184      c3             ret
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r

<!-- evidence_assembler: used 19901/60000 chars across 9 tools -->