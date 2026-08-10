## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=669cf448a0b2b308 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=95, sha256=669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2
  Anomalies (14): CrossSectionJump×13 (code), DelayImports×256 (imports), DynamicString×2 (strings), GuiSubsystemNoWindowApi (headers), HighXrefLoopingFunction×19 (code), InvalidChecksum (integrity), ManyHighValueImmediates×4 (code), ManyUniqueImmediateBytes (code), SequentialFunction×2 (code), SpaghettiFunction×20 (code), StackArrayInitialisationX64×2 (code), UnsignedMicrosoft×4 (integrity), WeirdDebugInfoType (headers), XorInLoop×12 (code)
  High-signal anomaly locations: DynamicString@836330,195958; GuiSubsystemNoWindowApi@372; HighXrefLoopingFunction@11344,11568,48520; ManyHighValueImmediates@108120,121844,194980; ManyUniqueImmediateBytes@194980; SequentialFunction@45744,47568; SpaghettiFunction@41920,113064,121844; XorInLoop@195802,493598,493614
  YARA (signal): KeyloggerApi
  YARA (info, 4 total): MSVC_2015_linker, msvs_2015__14_0__rich, AutorunKey, RunShell
  Functions (15): #0@544496, sub_14006ff1c@455452, #1@775012, sub_140042368@268136, sub_1400426a4@268964, #0@652336, #0@652860, #0@653000, #0@653268, #0@652476, #0@652604, #0@652732, #0@653140, sub_14009631c@612124, #1@778904
  Top high-signal imports (score≥8, 11 of 637):
    [10] user32.DestroyWindow (delayed) ×15
    [10] user32.DestroyIcon (delayed) ×7
    [10] kernel32.HeapDestroy ×5
    [10] user32.DestroyCursor (delayed) ×3
    [10] user32.GetDesktopWindow (delayed) ×3
    [10] kernel32.IsDebuggerPresent ×2
    [9] advapi32.RegSetValueExW ×4
    [9] advapi32.RegCreateKeyExW ×3
    [8] ole32.CoDisconnectObject ×3
    [8] kernel32.VirtualAlloc
    [8] kernel32.VirtualProtect
  Mid-signal imports: user32.SendMessageW (delayed), kernel32.QueryPerformanceCounter, kernel32.TerminateProcess, kernel32.GetProcAddress, kernel32.DeleteFileW, kernel32.LoadLibraryExW, kernel32.LoadLibraryW, kernel32.LoadLibraryExA, kernel32.GetModuleHandleW, mfplat.MFCreateFile (delayed), advapi32.RegOpenKeyExW, kernel32.CreateFileW, kernel32.GetModuleHandleExW, advapi32.RegQueryValueExW
  (low-signal/noise imports: 612 omitted)
  ⚠ Constants/registry (3): registry::HKEY_CURRENT_USER×17, registry::HKEY_USERS×3, registry::HKEY_LOCAL_MACHINE×5
    Constants/exception (1): exception::C++ exception
    Constants/guid (7): guid::IUnknown, guid::IClassFactory, guid::IDispatch, guid::IMFByteStream, guid::IAccessible, guid::IEnumVARIANT, guid::IOleWindow
    Constants/oid (36): oid::signedData, oid::sha1, oid::spcIndirectDataContext, oid::spcPEImageData, oid::sha1WithRSAEncryption, oid::stateOrProvinceName, oid::localityName, oid::commonName
    Constants/hash (1): hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15
  Strings/urls (2 total): http://xml.org/s../lexical-handler, http://www.w3.or..LSchema-instance
  Strings/registry (8 total): Software\Microso..tVersion\RunOnce, Software\Microso..ommon\FilesPaths, Software\Microso..s\CurrentVersion, Software\Microso..0\Lync\Recording, Software\Microso..Office\16.0\Lync, Software\Microsoft\DirectUI, SOFTWARE\Microso..racing\UcClient\
  Strings/apis (1 total): DisableProcessCallbackFilter
  Strings (other, 289 items, omitted)
  Carved files (16): DIB@1527048 (270376 bytes), DIB@1797424 (38056 bytes), DIB@1835480 (26600 bytes), DIB@1862080 (21640 bytes), DIB@1883720 (16936 bytes), DIB@1900656 (14920 bytes), DIB@1915576 (9640 bytes), DIB@1925216 (6760 bytes), DIB@1931976 (4264 bytes), DIB@1936240 (2440 bytes)
  Virtual files (20): PNG/5027/en-us, PNG/5028/en-us, PNG/5029/en-us, WEVT_TEMPLATE/1/en-us, ICO/1/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, ICO/5/en-us, ICO/6/en-us
  Recovered structures (156): MZ, RichHeader, PE, OptionalHeader, Sections, DebugDirectory, Debug.Reserved10, Debug.Codeview, advapi32.FT, gdiplus.FT, kernel32.FT, ole32.FT, oleaut32.FT, vcruntime140.FT, msvcp140.FT
  Decompilations (3 top functions):
    ### 544496 (#0, score=?)
```c
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 DirectUI::HWNDElementAccessible.#0(int64_t *param_1,int64_t *param_2,int64_t **param_3)

{
    undefined8 uVar1;
    
    if (param_3 == 0x0) {
        uVar1 = 0x80004003;
    }
    else {
        *param_3 = 0x0;
        if ((((*param_2 == IUnknown) && (param_2[1] == [0x0x1400e7350])) ||
            ((*param_2 == IDispatch && (param_2[1] == [0x0x1400e7488])))) ||
           ((*param_2 == IAccessible && (param_2[1] == [0x0x1400f9d98])))) {
            *param_3 = param_1;
            (**(*param_1 + 8))();
            uVar1 = 0;
        }
        else {
            uVar1 = 0x80004002;
        }
    }
    return uVar1;
}
```
    ### 455452 (sub_14006ff1c, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_14006ff1c(int64_t param_1,undefined8 *param_2,char param_3)

{
    uint32_t uVar1;
    int32_t iVar2;
    undefined8 uVar3;
    uint64_t uVar4;
    int64_t *piVar5;
    int64_t *piStackX_10;
    
    if (param_2 == 0x0) {
        return 0x80070057;
    }
    *param_2 = 0;
    if ((*(param_1 + 0x88) & 1) == 0) {
        return 0x80004005;
    }
    if (param_3 == '\0') {
        piVar5 = param_1 + 0x110;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar3 = (*user32.CallWindowProcW (delayed))
                          (*(param_1 + 0xb8), *(param_1 + 0xa8), 0x3d, 0xffffffff, 0xfffffffffffffffc);
        iVar2 = jmp_oleacc.ObjectFromLresult (delayed)(uVar3, &IAccessible, 0xffffffff, &piStackX_10);
        if (iVar2 < 0) {
            uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)
                              (*(param_1 + 0xa8), 0xfffffffc, &IAccessible, &piStackX_10);
            if (uVar1 < 0) {
                return uVar1;
            }
        }
        uVar1 = sub_1400853e4(param_1, piStackX_10, piVar5);
    }
    else {
        piVar5 = param_1 + 0x98;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)(*(param_1 + 0xa8), 0, &IAccessible, &piStackX_10);
        if (uVar1 < 0) {
            return uVar1;
        }
        uVar1 = sub_140085340(param_1, piStackX_10, piVar5);
    }
    (**(*piStackX_10 + 0x10))();
    if (uVar1 < 0) {
        return uVar1;
    }
code_r0x000140070045:
    uVar4 = (****piVar5)(*piVar5, &IAccessible, param_2);
    return uVar4;
}
```
    ### 775012 (#1, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 *
DirectUI::GridLayout.#1
          (int64_t param_1,undefined8 *param_2,int64_t param_3,uint32_t param_4,uint32_t param_5,undefined8 param_6)

{
    int64_t **ppiVar1;
    undefined8 uVar2;
    uint32_t uVar3;
    int32_t iVar4;
    int64_t iVar5;
    int64_t iVar6;
    uint32_t *puVar7;
    uint32_t *puVar8;
    int32_t *piVar9;
    undefined8 uVar10;
    uint64_t uVar11;
    uint32_t *puVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint64_t uVar15;
    uint64_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    int64_t *piVar20;
    int32_t iVar21;
    uint64_t uVar22;
    uint32_t *puVar23;
    uint32_t uVar24;
    undefined8 uStackX_18;
    uint32_t uStackX_20;
    uint32_t uStack_a8;
    int32_t iStack_a4;
    int64_t iStack_a0;
    int64_t iStack_98;
    uint32_t uStack_90;
    int32_t iStack_88;
    uint32_t uStack_84;
    uint32_t uStack_70;
    uint32_t uStack_6c;
    undefined8 uStack_68;
    int32_t *piStack_60;
    int64_t iStack_58;
    
    *(param_1 + 0x18) = 1;
    uVar3 = sub_1400d0814();
    uVar16 = uVar3;
    if ((*(param_3 + 0x88) & 4) == 0) {
        iVar5 = *([0x0x140150458] + 0x20);
    }
    else {
        iVar5 = sub_140077720(param_3, [0x0x140150458], 2);
    }
    uVar2 = *(iVar5 + 8);
    if ((*(param_1 + 0x28) & 2) == 0) {
        uVar16 = *(param_1 + 0x20);
    }
    else {
        uVar24 = *(param_1 + 0x24);
        if (uVar24 != 1) {
            uVar16 = ((uVar24 - 1) + uVar3) / uVar24;
        }
    }
    if ((*(param_1 + 0x28) & 1) == 0) {
        uVar24 = *(param_1 + 0x24);
    }
    else {
        uVar19 = *(param_1 + 0x20);
        uVar24 = uVar3;
        if (uVar19 != 1) {
            uVar24 = ((uVar19 - 1) + uVar3) / uVar19;
        }
    }
    ppiVar1 = param_1 + 0x30;
    if (*ppiVar1 != 0x0) {
        (*kernel32.HeapFree)();
        *ppiVar1 = 0x0;
    }
    if (*(param_1 + 0x38) != 0) {
        (*kernel32.HeapFree)();
      
```

## capa evidence (47 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (4): get common file path, check if file exists, get file size, get file version info
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (3): query environment variable, get disk information, check OS version
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (2): encode data using XOR, encrypt data using chaskey
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Collection', 'Input Capture', 'Keylogging'], 'tactic': 'Collection', 'technique': 'Input Capture', 'subtechnique': 'Keylogging', 'id': 'T1056.001'} (1): log keystrokes via polling
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (1): delete registry key
  ATT&CK {'parts': ['Persistence', 'Boot or Logon Autostart Execution', 'Registry Run Keys / Startup Folder'], 'tactic': 'Persistence', 'technique': 'Boot or Logon Autostart Execution', 'subtechnique': 'Registry Run Keys / Startup Folder', 'id': 'T1547.001'} (1): persist via Run registry key
  All rules (1): check for time delay via GetTickCount

## pe_imports (338 imports, 6 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  set_registry_value (RegSetValue) [T1112]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (18)
  Rules: domain, IP, contains_base64, Dropper_Strings, url, IsPE64, IsWindowsGUI, HasOverlay, HasDigitalSignature, HasDebugData, HasRichSignature, Check_OutputDebugStringA_iat, anti_dbg, screenshot, keylogger, win_mutex, win_registry, win_files_operation

## FLOSS strings (6107 total)
  (other strings, 80 items omitted)

<!-- evidence_assembler: used 11095/28000 chars across 5 tools -->