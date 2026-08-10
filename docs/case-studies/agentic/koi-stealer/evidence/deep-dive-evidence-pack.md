## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=e29d2bd946212328 | packaging=v6.1 -->

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
  ⚠ Constants/registry (2): registry::HKEY_CURRENT_USER×3, registry::HKEY_LOCAL_MACHINE×2
  ⚠ Constants/crypto (1): crypto::PKCS_DigestDecoration_SHA256__8_byt_19×2
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

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 5 functions (asm)
  ### 0x004b5eec
```c
┌ 501: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_24h @ ebp-0x24
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_38h @ ebp-0x38
│           ; var int32_t var_3ch @ ebp-0x3c
│           ; var int32_t var_40h @ ebp-0x40
│           ; var int32_t var_5ch @ ebp-0x5c
│           0x004b5eec      55             push ebp
│           0x004b5eed      8bec           mov ebp, esp
│           0x004b5eef      83c4a4         add esp, 0xffffffa4
│           0x004b5ef2      53             push ebx
│           0x004b5ef3      56             push esi
│           0x004b5ef4      57             push edi
│           0x004b5ef5      33c0           xor eax, eax
│           0x004b5ef7      8945c4         mov dword [var_3ch], eax
│           0x004b5efa      8945c0         mov dword [var_40h], eax
│           0x004b5efd      8945a4         mov dword [var_5ch], eax
│           0x004b5f00      8945d0         mov dword [var_30h], eax
│           0x004b5f03      8945c8         mov dword [var_38h], eax
│           0x004b5f06      8945cc         mov dword [var_34h], eax
│           0x004b5f09      8945d4         mov dword [var_2ch], eax
│           0x004b5f0c      8945d8         mov dword [var_28h], eax
│           0x004b5f0f      8945ec         mov dword [var_14h], eax
│           0x004b5f12      b8b8144b00     mov eax, 0x4b14b8
│           0x004b5f17      e8b072f5ff     call 0x40d1cc
│           0x004b5f1c      33c0           xor eax, eax
│           0x004b5f1e      55             push ebp
│           0x004b5f1f      68e2654b00     push 0x4b65e2
│           0x004b5f24      64ff30         push dword fs:[eax]
│           0x004b5f27      648920         mov dword fs:[eax], esp
│           0x004b5f2a      33d2           xor edx, edx
│           0x004b5f2c      55             push ebp
│           0x004b5f2d      689e654b00     push 0x4b659e
│           0x004b5f32      64ff32         push dword fs:[edx]
│           0x004b5f35      648922         mov dword fs:[edx], esp
│           0x004b5f38      a134e64b00     mov eax, dword [0x4be634]   ; [0x4be634:4]=0
│           0x004b5f3d      e8a29dffff     call 0x4afce4
│           0x004b5f42      e8f598ffff     call 0x4af83c
│           0x004b5f47      8d55ec   
```
  ### 0x0040d0a0
```c
┌ 167: sym.SetupLdr.exe___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x0040d0a0      55             push ebp
│       ╎   0x0040d0a1      8bec           mov ebp, esp
│       ╎   0x0040d0a3      51             push ecx
│       ╎   0x0040d0a4      53             push ebx
│       ╎   0x0040d0a5      56             push esi
│       ╎   0x0040d0a6      57             push edi
│       ╎   0x0040d0a7      33c0           xor eax, eax
│       ╎   0x0040d0a9      8945fc         mov dword [var_4h], eax
│       ╎   0x0040d0ac      33c0           xor eax, eax
│       ╎   0x0040d0ae      55             push ebp
│       ╎   0x0040d0af      6841d14000     push 0x40d141
│       ╎   0x0040d0b4      64ff30         push dword fs:[eax]
│       ╎   0x0040d0b7      648920         mov dword fs:[eax], esp
│       ╎   0x0040d0ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0bd      50             push eax
│       ╎   0x0040d0be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0c1      50             push eax
│       ╎   0x0040d0c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0c5      50             push eax
│       ╎   0x0040d0c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0c9      50             push eax
│       ╎   0x0040d0ca      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0cd      50             push eax
│       ╎   0x0040d0ce      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0d1      50             push eax
│       ╎   0x0040d0d2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0d5      50             push eax
│       ╎   0x0040d0d6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0d9      50             push eax
│       ╎   0x0040d0da      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0dd      50             push eax
│       ╎   0x0040d0de      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0e1      50             push eax
│       ╎   0x0040d0e2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0e5      50             push eax
│       ╎   0x0040d0e6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0e9      50             push eax
│       ╎   0x0040d0ea      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0ed      50             push eax
│       ╎   0x0040d0ee      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0f1      50             push eax
│       ╎
```
  ### 0x0040ccb0
```c
; CALL XREF from sym.SetupLdr.exe___dbk_fcall_wrapper @ 0x40d12f(x)
┌ 1007: fcn.0040ccb0 ();
│           0x0040ccb0      55             push ebp
│           0x0040ccb1      8bec           mov ebp, esp
│           0x0040ccb3      e8f4ffffff     call fcn.0040ccac
│           0x0040ccb8      e8efffffff     call fcn.0040ccac
│           0x0040ccbd      e8eaffffff     call fcn.0040ccac
│           0x0040ccc2      e8e5ffffff     call fcn.0040ccac
│           0x0040ccc7      e8e0ffffff     call fcn.0040ccac
│           0x0040cccc      e8dbffffff     call fcn.0040ccac
│           0x0040ccd1      e8d6ffffff     call fcn.0040ccac
│           0x0040ccd6      e8d1ffffff     call fcn.0040ccac
│           0x0040ccdb      e8ccffffff     call fcn.0040ccac
│           0x0040cce0      e8c7ffffff     call fcn.0040ccac
│           0x0040cce5      e8c2ffffff     call fcn.0040ccac
│           0x0040ccea      e8bdffffff     call fcn.0040ccac
│           0x0040ccef      e8b8ffffff     call fcn.0040ccac
│           0x0040ccf4      e8b3ffffff     call fcn.0040ccac
│           0x0040ccf9      e8aeffffff     call fcn.0040ccac
│           0x0040ccfe      e8a9ffffff     call fcn.0040ccac
│           0x0040cd03      e8a4ffffff     call fcn.0040ccac
│           0x0040cd08      e89fffffff     call fcn.0040ccac
│           0x0040cd0d      e89affffff     call fcn.0040ccac
│           0x0040cd12      e895ffffff     call fcn.0040ccac
│           0x0040cd17      e890ffffff     call fcn.0040ccac
│           0x0040cd1c      e88bffffff     call fcn.0040ccac
│           0x0040cd21      e886ffffff     call fcn.0040ccac
│           0x0040cd26      e881ffffff     call fcn.0040ccac
│           0x0040cd2b      e87cffffff     call fcn.0040ccac
│           0x0040cd30      e877ffffff     call fcn.0040ccac
│           0x0040cd35      e872ffffff     call fcn.0040ccac
│           0x0040cd3a      e86dffffff     call fcn.0040ccac
│           0x0040cd3f      e868ffffff     call fcn.0040ccac
│           0x0040cd44      e863ffffff     call fcn.0040ccac
│           0x0040cd49      e85effffff     call fcn.0040ccac
│           0x0040cd4e      e859ffffff     call fcn.0040ccac
│           0x0040cd53      e854ffffff     call fcn.0040ccac
│           0x0040cd58      e84fffffff     call fcn.0040ccac
│           0x0040cd5d      e84affffff     call fcn.0040ccac
│           0x0040cd62      e845ffffff     call fcn.0040ccac
│           0x0040cd67      e840ffffff     call fcn.0040ccac
│           0x0040cd6c      e83bffffff    
```
  ### 0x0040ccac
```c
; XREFS(200)
┌ 1: fcn.0040ccac ();
└           0x0040ccac      c3             ret
```
  ### 0x004541a8
```c
┌ 16: sym.SetupLdr.exe_TMethodImplementationIntercept (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           0x004541a8      55             push ebp
│           0x004541a9      8bec           mov ebp, esp
│           0x004541ab      8b550c         mov edx, dword [arg_ch]
│           0x004541ae      8b4508         mov eax, dword [arg_8h]
│           0x004541b1      e802000000     call fcn.004541b8
│           0x004541b6      5d             pop ebp
└           0x004541b7      c3             ret
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r

<!-- evidence_assembler: used 18644/60000 chars across 9 tools -->