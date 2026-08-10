## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=ba3558c89e9ff2e3 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=45, sha256=ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7
  Anomalies (10): DelayImports×60 (imports), DynamicString (strings), GuiSubsystemNoWindowApi (headers), HugeGapBetweenFunctions×2 (code), InvalidChecksum (integrity), ManyHighValueImmediates×2 (code), PossiblePackerApiDynamicImport (imports), StackArrayInitialisationX64 (code), UnsignedMicrosoft×4 (integrity), WeirdDebugInfoType (headers)
  High-signal anomaly locations: DynamicString@30662; GuiSubsystemNoWindowApi@364; ManyHighValueImmediates@28680,34268
  YARA (info, 2 total): MSVC_2015_linker, msvs_2015__14_0__rich
  Functions (15): sub_14000c6bc@47804, sub_14000ca98@48792, #0@8172, #0@46816, sub_140009104@34052, sub_14000b774@43892, sub_14000e7b0@56240, sub_1400091dc@34268, sub_140008864@31844, sub_140008ad0@32464, sub_140008a6c@32364, sub_140007a63@28259, sub_140001218@1560, delay#0 (delaystub)@27932, delay#0 (delaystub)@28280
  Top high-signal imports (score≥8, 6 of 210):
    [10] user32.DestroyWindow (delayed) ×3
    [10] kernel32.HeapDestroy ×2
    [10] kernel32.IsDebuggerPresent
    [9] advapi32.RegCreateKeyExW
    [9] advapi32.RegSetValueExW
    [8] kernel32.VirtualProtect
  Mid-signal imports: kernel32.QueryPerformanceCounter, kernel32.CreateThread, kernel32.OpenProcess, kernel32.TerminateProcess, user32.SendMessageW (delayed), kernel32.GetProcAddress, kernel32.LoadLibraryW, kernel32.LoadLibraryExA, kernel32.LoadLibraryExW, kernel32.GetModuleHandleW, advapi32.RegOpenKeyExW, advapi32.RegQueryValueExW, kernel32.GetModuleHandleExW
  (low-signal/noise imports: 191 omitted)
  ⚠ Constants/registry (3): registry::HKEY_CURRENT_USER×3, registry::HKEY_USERS×2, registry::HKEY_LOCAL_MACHINE×2
    Constants/exception (1): exception::C++ exception
    Constants/guid (1): guid::IUnknown
    Constants/oid (36): oid::signedData, oid::sha1, oid::spcIndirectDataContext, oid::spcPEImageData, oid::sha1WithRSAEncryption, oid::countryName, oid::stateOrProvinceName, oid::localityName
    Constants/hash (1): hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15
  Strings/registry (1 total): SOFTWARE\Microso..racing\UcClient\
  Strings/apis (6 total): PrepareProcessCommand, LogCheckerHiddenRootWindow, HandleCommandResult, VirtualAlloc, ProcessCommand, MaxFileSize
  Strings (other, 293 items, omitted)
  Carved files (31): DIB@188256 (270376 bytes), DIB@458632 (38056 bytes), DIB@496688 (26600 bytes), DIB@523288 (21640 bytes), DIB@544928 (16936 bytes), DIB@561864 (14920 bytes), DIB@576784 (9640 bytes), DIB@586424 (6760 bytes), DIB@593184 (4264 bytes), DIB@597448 (2440 bytes)
  Virtual files (34): ICO/1/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, ICO/5/en-us, ICO/6/en-us, ICO/7/en-us, ICO/8/en-us, ICO/9/en-us, ICO/10/en-us
  Recovered structures (169): MZ, RichHeader, PE, OptionalHeader, Sections, DebugDirectory, Debug.Reserved10, Debug.Codeview, advapi32.FT, kernel32.FT, ole32.FT, vcruntime140.FT, msvcp140.FT, api-ms-win-crt-heap-l1-1-0.FT, api-ms-win-crt-runtime-l1-1-0.FT
  Decompilations (3 top functions):
    ### 47804 (sub_14000c6bc, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

int32_t sub_14000c6bc(int64_t param_1)

{
    int32_t iVar1;
    int64_t iVar2;
    int64_t iVar3;
    int64_t iVar4;
    undefined8 uVar5;
    undefined4 uVar6;
    bool bVar7;
    
    iVar4 = 0;
    LOCK();
    bVar7 = *(param_1 + 0x270) == 0;
    if (bVar7) {
        *(param_1 + 0x270) = 0;
    }
    UNLOCK();
    if (!bVar7) {
        return 0;
    }
    if (*(param_1 + 0x270) != 0) {
        return 0;
    }
    iVar1 = sub_14000db94(param_1, param_1);
    if (iVar1 < 0) {
        if ([0x0x14001e260] == 0x14001e260) {
            return iVar1;
        }
        if ((*([0x0x14001e260] + 0x3c) & 1) == 0) {
            return iVar1;
        }
        if (*([0x0x14001e260] + 0x39) < 2) {
            return iVar1;
        }
        uVar6 = 10;
        uVar5 = *([0x0x14001e260] + 0x30);
    }
    else {
        iVar2 = sub_140006dc4(0x20);
        iVar3 = iVar4;
        if (iVar2 != 0) {
            iVar3 = sub_14000d398(iVar2, 0xffffffff80000003, 0xf003f);
        }
        if (*(param_1 + 0x250) != 0x0) {
            (**(**(param_1 + 0x250) + 0x10))();
        }
        *(param_1 + 0x250) = iVar3;
        if (iVar3 == 0) {
            if ([0x0x14001e260] == 0x14001e260) {
                return -0x7ff8fff2;
            }
            if ((*([0x0x14001e260] + 0x3c) & 1) == 0) {
                return -0x7ff8fff2;
            }
            if (*([0x0x14001e260] + 0x39) < 2) {
                return -0x7ff8fff2;
            }
            uVar6 = 0xb;
        }
        else {
            iVar2 = sub_140006dc4(0x20);
            iVar3 = iVar4;
            if (iVar2 != 0) {
                iVar3 = sub_14000d398(iVar2, 0xffffffff80000001, 0xf003f);
            }
            if (*(param_1 + 600) != 0x0) {
                (**(**(param_1 + 600) + 0x10))();
            }
            *(param_1 + 600) = iVar3;
            if (iVar3 == 0) {
                if ([0x0x14001e260] == 0x14001e260) {
                    return -0x
```
    ### 48792 (sub_14000ca98, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_14000ca98(int64_t param_1,int64_t param_2,int64_t **param_3)

{
    int64_t *piVar1;
    
    if (param_2 == -0x7ffffffe) {
        piVar1 = *(param_1 + 0x260);
    }
    else if (param_2 == -0x7fffffff) {
        piVar1 = *(param_1 + 600);
    }
    else if (param_2 == -0x7ffffffd) {
        piVar1 = *(param_1 + 0x250);
    }
    else {
        if (param_2 != -0x80000000) {
            return 0x80070057;
        }
        piVar1 = *(param_1 + 0x268);
    }
    if (*param_3 != piVar1) {
        if (piVar1 != 0x0) {
            (**(*piVar1 + 8))(piVar1);
        }
        if (*param_3 != 0x0) {
            (**(**param_3 + 0x10))();
        }
        *param_3 = piVar1;
    }
    return 0;
}
```
    ### 8172 (#0, score=?)
```c
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 CLync99MsoComponentHost.#0(int64_t *param_1,int64_t *param_2,int64_t **param_3)

{
    undefined8 uVar1;
    
    if (param_3 == 0x0) {
        uVar1 = 0x80004003;
    }
    else {
        *param_3 = 0x0;
        if ((((*param_2 == IUnknown) && (param_2[1] == [0x0x140010d20])) ||
            ((*param_2 == [0x0x1400106d8] && (param_2[1] == [0x0x1400106e0])))) ||
           ((*param_2 == [0x0x1400106e8] && (param_2[1] == [0x0x1400106f0])))) {
            (**(*param_1 + 8))();
            uVar1 = 0;
            *param_3 = param_1;
        }
        else {
            uVar1 = 0x80004002;
        }
    }
    return uVar1;
}
```

## capa evidence (13 total, showing top 13)
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (2): link function at runtime on Windows, parse PE header
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (1): query environment variable
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  ATT&CK {'parts': ['Discovery', 'Application Window Discovery'], 'tactic': 'Discovery', 'technique': 'Application Window Discovery', 'subtechnique': '', 'id': 'T1010'} (1): find graphical window
  All rules (8): create directory, move file, terminate process, set registry value, create thread, enumerate PE sections, contains PDB path, contain a thread local storage (.tls) section

## pe_imports (150 imports, 5 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  set_registry_value (RegSetValue) [T1112]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]

## YARA matches (15)
  Rules: domain, IP, contains_base64, url, IsPE64, IsWindowsGUI, HasOverlay, HasDigitalSignature, HasDebugData, HasRichSignature, Check_OutputDebugStringA_iat, anti_dbg, keylogger, win_mutex, win_registry

## FLOSS strings (1262 total)
  paths (1): P:\Target\x64\ship\lync\x-none\lync99.pdb
  base64 (1): 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
  apis (1): VirtualAlloc
  (other strings, 77 items omitted)

<!-- evidence_assembler: used 8644/28000 chars across 5 tools -->