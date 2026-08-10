## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=0c00aedf97071653 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=105, sha256=0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5
  Anomalies (15): BigBufferNoXrefMediumToHighEntropy×2 (entropy), CrossSectionJump (code), ExecutableSectionNoCode (sections), HugeFunctionGapAtSectionBoundary (code), InvalidSizeOfInitializedData (sections), ManyHighValueImmediates×2 (code), ManyUniqueImmediateBytes×2 (code), RelocSectionNoRelocation (sections), RichUnknownTool (rich), SectionWX (sections), SequentialFunction×2 (code), SpaghettiFunction (code), UnbalancedVirtualPhysicalRatio (sections), WeirdDebugInfoType (headers), XorInLoop×4 (code)
  High-signal anomaly locations: ManyHighValueImmediates@112276,840704; ManyUniqueImmediateBytes@95904,840704; SequentialFunction@840704,843622; SpaghettiFunction@95904; XorInLoop@3320,23277,23849
  YARA (info, 5 total): MSVC_2017_linker, visual_studio_2017_version_15_9_4_rich, ElevatePrivileges, RunShell, msvc_general_x64
  Functions (15): sub_14000bbe4@45028, sub_14001b690@109200, sub_1400ce000@840704, sub_14001b6d0@109264, sub_14001be90@111248, sub_14000663c@23100, sub_140006878@23672, sub_140001878@3192, sub_14001af50@107344, sub_140011828@68648, sub_140010104@62724, sub_1400104ac@63660, sub_14001c850@113744, sub_14000f680@60032, sub_140003508@10504
  Top high-signal imports (score≥8, 8 of 181):
    [10] kernel32.IsDebuggerPresent ×3
    [10] userenv.DestroyEnvironmentBlock ×2
    [9] advapi32.RegCreateKeyExW ×3
    [9] advapi32.RegSetValueExW
    [8] advapi32.AdjustTokenPrivileges ×2
    [8] advapi32.OpenSCManagerW
    [8] advapi32.StartServiceW
    [8] kernel32.VirtualAlloc
  Mid-signal imports: user32.SendMessageW, advapi32.OpenProcessToken, kernel32.TerminateProcess, advapi32.CreateProcessAsUserW, kernel32.OpenProcess, kernel32.QueryPerformanceCounter, kernel32.GetProcAddress, kernel32.DeleteFileW, kernel32.LoadLibraryExA, kernel32.LoadLibraryW, kernel32.GetModuleHandleW, advapi32.RegOpenKeyExW
  (low-signal/noise imports: 161 omitted)
  - Constants/registry (1): registry::HKEY_LOCAL_MACHINE
    Constants/exception (1): exception::C++ exception
  Strings/urls (2 total): https://forums.m..ads/59268/
  Strings/registry (1 total): SOFTWARE\Microso..mmandStore\shell
  Strings/paths (1 total): E:\Projects\NSud..se\x64\NSudo.pdb
  Strings/apis (4 total): ShowWindowMode, GetDpiForMonitor, SettingsGroupText, CurrentProcess
  Strings (other, 292 items, omitted)
  Carved files (8): DIB@192040 (1128 bytes), DIB@193168 (1720 bytes), DIB@194888 (2440 bytes), DIB@197328 (4264 bytes), DIB@201592 (6760 bytes), DIB@208352 (9640 bytes), DIB@217992 (16936 bytes), PNG@234928 (4763 bytes)
  Virtual files (26): CONFIG/101/unk, STRING/2000/zh-hans, STRING/2000/en, STRING/2000/fr, STRING/2000/zh-tw, STRING/2002/zh-hans, STRING/2002/en, STRING/2002/fr, STRING/2002/zh-tw, STRING/2003/zh-hans
  Recovered structures (120): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, comdlg32.FT, gdi32.FT, kernel32.FT, shell32.FT, user32.FT, userenv.FT, wtsapi32.FT, msvcp60.FT, msvcrt.FT
  Decompilations (3 top functions):
    ### 45028 (sub_14000bbe4, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

int32_t * sub_14000bbe4(int32_t *param_1)

{
    int32_t *piVar1;
    int32_t iVar2;
    
    *param_1 = 0;
    piVar1 = param_1 + 2;
    *(param_1 + 6) = 0;
    *(param_1 + 8) = 7;
    *piVar1 = 0;
    *(param_1 + 10) = 0;
    *(param_1 + 0xc) = 0;
    *(param_1 + 0xe) = 0;
    *(param_1 + 0x10) = 0;
    iVar2 = sub_140003398(piVar1);
    *param_1 = iVar2;
    if (-1 < iVar2) {
        sub_140014530(piVar1, "\\NSudo.exe", 10);
        iVar2 = (*advapi32.RegOpenKeyExW)(0xffffffff80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CommandStore\\shell", 0, 0xf013f, param_1 + 10);
        *param_1 = iVar2;
        if (iVar2 == 0) {
            sub_14000eb58(param_1 + 0xc);
        }
    }
    return param_1;
}
```
    ### 109200 (sub_14001b690, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_14001b690(int32_t **param_1)

{
    int32_t *piVar1;
    code *pcVar2;
    undefined8 uVar3;
    
    piVar1 = *param_1;
    if ((*piVar1 == -0x1f928c9d) && (piVar1[6] == 4)) {
        if ((piVar1[8] + 0xe66cfae0U < 3) || (piVar1[8] == 0x1994000)) {
            jmp_msvcrt.terminate();
            pcVar2 = swi(3);
            uVar3 = (*pcVar2)();
            return uVar3;
        }
    }
    return 0;
}
```
    ### 840704 (sub_1400ce000, score=?)
```c
/* WARNING: Possible PIC construction at 0x0001400ce92d: Changing call to branch */
/* WARNING: Possible PIC construction at 0x0001400ce93a: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x0001400ce932) */
/* WARNING: Removing unreachable block (ram,0x0001400ce93f) */
/* WARNING: Removing unreachable block (ram,0x0001400ce94b) */
/* WARNING: Removing unreachable block (ram,0x0001400ce94d) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_1400ce000(void)

{
    int64_t iVar1;
    int32_t *piVar2;
    undefined *puVar3;
    undefined8 *puVar4;
    undefined *unaff_RBP;
    
    piVar2 = 0x140041400;
    iVar1 = 0;
    do {
        piVar2[0xe3] = ~piVar2[0xe3];
        piVar2[0xb8] = piVar2[0xb8] ^ 0x35fc132e;
        piVar2[0x6d] = piVar2[0x6d] ^ 0x5f463a43;
        piVar2[0xdf] = ~piVar2[0xdf];
        piVar2[0xe0] = piVar2[0xe0] + 0x737449d7;
        piVar2[0x4d] = piVar2[0x4d] + -0x2305235a;
        piVar2[0xd8] = piVar2[0xd8] ^ 0x56023e06;
        piVar2[0x15] = piVar2[0x15] + -0x391c7d14;
        piVar2[0x89] = ~piVar2[0x89];
        piVar2[0x1b] = ~piVar2[0x1b];
        piVar2[0x5c] = piVar2[0x5c] + 0x46bf69a6;
        piVar2[0x14] = ~piVar2[0x14];
        piVar2[0x59] = piVar2[0x59] + 0x58a737ac;
        piVar2[0x41] = piVar2[0x41] ^ 0x12b4474c;
        piVar2[0x31] = piVar2[0x31] + 0x44bb0f76;
        piVar2[0x8e] = piVar2[0x8e] + 0x54d7471f;
        piVar2[0x43] = ~piVar2[0x43];
        piVar2[0x24] = ~piVar2[0x24];
        piVar2[0xf6] = piVar2[0xf6] ^ 0x6b7270ca;
        piVar2[0xa9] = ~piVar2[0xa9];
        *piVar2 = *piVar2 + -0x13f24793;
        piVar2[0x3e] = piVar2[0x3e] + 0x506360f3;
        piVar2[0x53] = piVar2[0x53] + 0xa922714;
        piVar2[0x76] = piVar2[0x76] + 0x31645598;
        piVar2[0x49] = piVar2[0x49] + -0x19664f67;
        piVar2[0xd] = piVar2[0xd] ^ 0x18ec3a51;
        piVar2[0x71] = piVar2[0x71] + 0x322e17bd;
        piVar2[10] = piVar2[10] ^ 0x401c6269;
        piVar2[0x32] = piVar2[0x32]
```

## capa evidence (27 total, showing top 15)
  ATT&CK {'parts': ['Execution', 'Command and Scripting Interpreter'], 'tactic': 'Execution', 'technique': 'Command and Scripting Interpreter', 'subtechnique': '', 'id': 'T1059'} (1): accept command line arguments
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (1): query environment variable
  ATT&CK {'parts': ['Defense Evasion', 'File and Directory Permissions Modification'], 'tactic': 'Defense Evasion', 'technique': 'File and Directory Permissions Modification', 'subtechnique': '', 'id': 'T1222'} (1): set file attributes
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (1): delete registry key
  ATT&CK {'parts': ['Discovery', 'Process Discovery'], 'tactic': 'Discovery', 'technique': 'Process Discovery', 'subtechnique': '', 'id': 'T1057'} (1): enumerate processes on remote desktop session host
  ATT&CK {'parts': ['Privilege Escalation', 'Access Token Manipulation'], 'tactic': 'Privilege Escalation', 'technique': 'Access Token Manipulation', 'subtechnique': '', 'id': 'T1134'} (1): modify access privileges
  All rules (9): copy file, delete file, get file attributes, move file, write file on Windows, get graphical window text, create process on Windows, terminate process, set registry value

## pe_imports (181 imports, 6 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (15)
  Rules: domain, IP, contains_base64, url, IsPE64, IsWindowsGUI, HasDebugData, HasRichSignature, Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL, anti_dbg, escalate_priv, screenshot, win_registry, win_token

## FLOSS strings (2195 total)
  (other strings, 80 items omitted)

<!-- evidence_assembler: used 8574/28000 chars across 5 tools -->