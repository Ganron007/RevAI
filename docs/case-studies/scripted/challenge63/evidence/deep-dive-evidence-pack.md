## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=98ab99efa9cc35e8 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=125, sha256=98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648
  Anomalies (14): BigStringHiScore (strings), BoundImports (imports), CrossSectionJump (code), DynamicString×2 (strings), HugeStringBinary (strings), InvalidChecksum (integrity), ManyHighValueImmediates×3 (code), RichUnknownTool (rich), SequentialFunction (code), SpaghettiFunction×4 (code), StackArrayInitialisationX86 (code), UnbalancedVirtualPhysicalRatio (sections), UnsignedMicrosoft×3 (integrity), VeryHugeString (strings)
  High-signal anomaly locations: DynamicString@44457,32861; ManyHighValueImmediates@16732,24400,41752; SequentialFunction@4104; SpaghettiFunction@10799,16541,20149
  YARA (info, 3 total): MSVC_2002_linker, MSVC_2002_rich, ElevatePrivileges
  Functions (15): sub_101328a@75402, sub_1013ad1@77521, sub_100d2d1@50897, sub_10048c0@15552, sub_100a86d@40045, sub_1009693@35475, sub_1012fe0@74720, sub_1013dc2@78274, sub_1004ae1@16097, sub_100530d@18189, sub_1009108@34056, sub_100456a@14698, sub_10041bc@13756, sub_1004783@15235, sub_1004a5b@15963
  Top high-signal imports (score≥8, 23 of 290):
    [10] user32.DestroyWindow ×5
    [10] advapi32.GetSecurityDescriptorGroup ×4
    [10] advapi32.GetSecurityDescriptorOwner ×4
    [10] advapi32.GetSecurityDescriptorControl ×3
    [10] advapi32.GetSecurityDescriptorDacl ×3
    [10] advapi32.GetSecurityDescriptorSacl ×3
    [10] comctl32.ImageList_Destroy ×3
    [10] user32.DestroyMenu ×3
    [10] advapi32.InitializeSecurityDescriptor
    [10] advapi32.SetSecurityDescriptorDacl
    [10] advapi32.SetSecurityDescriptorGroup
    [10] advapi32.SetSecurityDescriptorOwner
    [10] advapi32.SetSecurityDescriptorSacl
    [10] user32.DestroyCaret
    [10] user32.DestroyIcon
    [10] user32.GetDesktopWindow
    [9] advapi32.RegCreateKeyW ×9
    [9] advapi32.RegSetValueExW ×7
    [9] advapi32.RegSetValueExA
    [9] advapi32.RegSetValueW
    [8] advapi32.RegConnectRegistryW ×3
    [8] advapi32.AdjustTokenPrivileges
    [8] advapi32.LookupPrivilegeValueW
  Mid-signal imports: user32.SendMessageW, user32.SendDlgItemMessageW, advapi32.OpenProcessToken, kernel32.DeleteFileW, kernel32.GetProcAddress, kernel32.LoadLibraryA, kernel32.LoadLibraryW, advapi32.RegOpenKeyExW, advapi32.RegOpenKeyW, kernel32.CreateFileW, kernel32.GetModuleHandleW, advapi32.RegQueryValueExA, advapi32.RegOpenKeyExA, advapi32.RegQueryValueExW
  (low-signal/noise imports: 253 omitted)
  * Constants/registry (3): registry::HKEY_CURRENT_USER×10, registry::HKEY_LOCAL_MACHINE×5, registry::HKEY_USERS×4
    Constants/guid (1): guid::IUnknown
    Constants/code (1): code::PEBx86
  Strings/registry (9 total): Software\Microso..\Policies\System, Software\Microso..egedit\Favorites, Software\Microso..\Applets\Regedit, HKEY_LOCAL_MACHINE, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_USER, HKEY_CURRENT_CONFIG, HKEY_DYN_DATA
  Strings/paths (1 total): C:\Program Files.. Files\qomag.exe
  Strings/apis (21 total): DisableRegistryTools, FindFlags, OriginalFilename, FileTimeToLocalFileTime, GetSecurityDescriptorGroup, SetSecurityDescriptorGroup, SetSecurityDescriptorDacl, SetSecurityDescriptorSacl, GetSecurityDescriptorControl, FileDescription, SetSecurityDescriptorOwner, CreateCaret, GetSecurityDescriptorOwner, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl
  Strings (other, 269 items, omitted)
  Carved files (12): DIB@369504 (744 bytes), DIB@370248 (296 bytes), DIB@370584 (744 bytes), DIB@371328 (296 bytes), DIB@371664 (744 bytes), DIB@372432 (296 bytes), DIB@372752 (296 bytes), DIB@373072 (296 bytes), DIB@373392 (296 bytes), DIB@373712 (296 bytes)
  Virtual files (96): CUR/12/en-us, ICO/1/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, ICO/5/en-us, ICO/6/en-us, ICO/7/en-us, ICO/8/en-us, ICO/9/en-us
  Recovered structures (338): MZ, RichHeader, PE, OptionalHeader, Sections, BoundImportTable, BoundImportNames, aclui.FT, advapi32.FT, authz.FT, comctl32.FT, gdi32.FT, kernel32.FT, shell32.FT, user32.FT
  Decompilations (3 top functions):
    ### 75402 (sub_101328a, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 __thiscall sub_101328a(int32_t param_1,undefined4 *param_2,int32_t param_3,int32_t *param_4)

{
    char cVar1;
    int32_t iVar2;
    int32_t *piVar3;
    undefined4 *puVar4;
    code **ppcVar5;
    uint32_t uVar6;
    undefined2 *puVar7;
    int32_t iStack_14;
    undefined4 *puStack_10;
    uint32_t uStack_c;
    undefined4 *puStack_8;
    
    if (param_2 != 0x0) {
        puStack_8 = param_2;
        iVar2 = PEBx86(0x18);
        if (iVar2 == 0) {
            piVar3 = 0x0;
        }
        else {
            piVar3 = (*ulib.ARRAY.ARRAY)();
        }
        if (piVar3 != 0x0) {
            cVar1 = (*ulib.ARRAY.Initialize)(0x32, 0x19);
            if (cVar1 != '\0') {
                uStack_c = 0;
                *(param_1 + 8) = *param_2;
                *(param_1 + 0xc) = param_2[1];
                *(param_1 + 0x10) = *(param_2 + 2);
                *(param_1 + 0x12) = *(param_2 + 10);
                do {
                    uVar6 = 0;
                    iStack_14 = 0;
                    puStack_10 = 0x0;
                    if (puStack_8[3] != 0) {
                        puVar7 = uStack_c + 0x12 + puStack_8;
                        do {
                            uVar6 = puStack_10;
                            if (param_2 + param_3 + -0x10 < puVar7 + -1) {
                                if (param_4 != 0x0) {
                                    *param_4 = param_3;
                                }
                                *(param_1 + 0x14) = piVar3;
                                return 1;
                            }
                            cVar1 = *(puVar7 + -1);
                            if (cVar1 != '\x01') {
                                if (cVar1 == '\x02') {
                                    iVar2 = PEBx86(0x18);
                                    if (iVar2 == 0) {
                                        puVar4 = 0x0;
                                    }
   
```
    ### 77521 (sub_1013ad1, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 __thiscall sub_1013ad1(int32_t param_1,undefined2 *param_2,int32_t param_3,int32_t *param_4)

{
    char cVar1;
    int32_t iVar2;
    int32_t *piVar3;
    undefined4 *puVar4;
    undefined2 *puVar5;
    int32_t iStack_14;
    uint32_t uStack_10;
    undefined2 *puStack_c;
    undefined2 *puStack_8;
    
    if (param_2 != 0x0) {
        puStack_c = param_2;
        iVar2 = PEBx86(0x18);
        if (iVar2 == 0) {
            piVar3 = 0x0;
        }
        else {
            piVar3 = (*ulib.ARRAY.ARRAY)();
        }
        if (piVar3 != 0x0) {
            cVar1 = (*ulib.ARRAY.Initialize)(0x32, 0x19);
            if (cVar1 != '\0') {
                iStack_14 = 0;
                *(param_1 + 8) = *param_2;
                *(param_1 + 10) = param_2[1];
                do {
                    uStack_10 = 0;
                    if (*(puStack_c + 2) != 0) {
                        puVar5 = puStack_c + 6;
                        do {
                            puStack_8 = puVar5 + -2;
                            if (param_2 + param_3 + -0x20 < puVar5 + -2) {
                                if (param_4 != 0x0) {
                                    *param_4 = param_3;
                                }
                                *(param_1 + 0xc) = piVar3;
                                return 1;
                            }
                            cVar1 = *(puVar5 + -3);
                            if (cVar1 != '\x01') {
                                if (cVar1 == '\x02') {
                                    iVar2 = PEBx86(0x18);
                                    if (iVar2 == 0) {
                                        puVar4 = 0x0;
                                    }
                                    else {
                                        puVar4 = sub_10138dd();
                                    }
                                    if (puVar4 != 0x0) {
                     
```
    ### 50897 (sub_100d2d1, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

uint32_t __fastcall sub_100d2d1(int32_t param_1)

{
    int32_t *piVar1;
    int32_t iVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    
    iVar2 = *(param_1 + 0x24);
    if (*(param_1 + 0x20) == 0) {
        if (iVar2 == 0) {
            *(param_1 + 0x2c) = 0x80000000;
            return 0;
        }
        if (iVar2 == 1) {
            *(param_1 + 0x2c) = 0x80000001;
            return 0;
        }
        if (iVar2 == 2) {
            *(param_1 + 0x2c) = 0x80000002;
            return 0;
        }
        if (iVar2 != 3) {
            if (iVar2 != 4) {
                return 0;
            }
            *(param_1 + 0x2c) = 0x80000005;
            return 0;
        }
        *(param_1 + 0x2c) = 0x80000003;
        return 0;
    }
    if (iVar2 < 0) goto code_r0x0100d334;
    if (1 < iVar2) {
        if (iVar2 == 2) {
            *(param_1 + 0x2c) = 0x80000002;
            goto code_r0x0100d334;
        }
        if (iVar2 == 3) {
            *(param_1 + 0x2c) = 0x80000003;
            goto code_r0x0100d334;
        }
        if (iVar2 != 4) goto code_r0x0100d334;
    }
    *(param_1 + 0x2c) = 0;
code_r0x0100d334:
    piVar1 = param_1 + 0x2c;
    uVar4 = 0;
    if (((*piVar1 != 0) && (uVar3 = (*advapi32.RegConnectRegistryW)(*(param_1 + 0x18), *piVar1, piVar1), uVar3 != 0)) &&
       (*piVar1 = 0, uVar4 = uVar3, 0 < uVar3)) {
        uVar4 = uVar3 & 0xffff | 0x80070000;
    }
    return uVar4;
}
```

## capa evidence (24 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (2): query or enumerate registry key, query or enumerate registry value
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (2): delete registry key, delete registry value
  ATT&CK {'parts': ['Collection', 'Clipboard Data'], 'tactic': 'Collection', 'technique': 'Clipboard Data', 'subtechnique': '', 'id': 'T1115'} (2): open clipboard, read clipboard data
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Collection', 'Input Capture', 'Keylogging'], 'tactic': 'Collection', 'technique': 'Input Capture', 'subtechnique': 'Keylogging', 'id': 'T1056.001'} (1): log keystrokes via polling
  ATT&CK {'parts': ['Execution', 'Command and Scripting Interpreter'], 'tactic': 'Execution', 'technique': 'Command and Scripting Interpreter', 'subtechnique': '', 'id': 'T1059'} (1): accept command line arguments
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (1): get file size
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (1): get hostname
  All rules (4): write clipboard data, delete file, read file on Windows, write file on Windows

## pe_imports (277 imports, 3 high-signal)
  set_registry_value (RegSetValue) [T1112]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (16)
  Rules: domain, IP, contains_base64, System_Tools, IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, Microsoft_Visual_Basic_v50, anti_dbg, escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation

## FLOSS strings (853 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x01015a38
```c
┌ 66: entry0 ();
│           0x01015a38      687a5a0101     push 0x1015a7a
│           0x01015a3d      33c9           xor ecx, ecx
│           0x01015a3f      64ff31         push dword fs:[ecx]
│           0x01015a42      648921         mov dword fs:[ecx], esp
│           0x01015a45      33d2           xor edx, edx
│           0x01015a47      6a10           push 0x10                   ; 16
│           0x01015a49      59             pop ecx
│       ┌─> 0x01015a4a      52             push edx
│       └─< 0x01015a4b      e2fd           loop 0x1015a4a
│           0x01015a4d      6a44           push 0x44                   ; 'D' ; 68
│           0x01015a4f      8bc4           mov eax, esp
│           0x01015a51      83ec10         sub esp, 0x10
│           0x01015a54      8bcc           mov ecx, esp
│           0x01015a56      51             push ecx
│           0x01015a57      50             push eax
│           0x01015a58      52             push edx
│           0x01015a59      52             push edx
│           0x01015a5a      52             push edx
│           0x01015a5b      52             push edx
│           0x01015a5c      52             push edx
│           0x01015a5d      52             push edx
│           0x01015a5e      688c5a0101     push 0x1015a8c              ; "C:\Program Files\Common Files\qomag.exe"
│           0x01015a63      52             push edx
│           0x01015a64      b9b81be677     mov ecx, 0x77e61bb8
│           0x01015a69      ffd1           call ecx
│           0x01015a6b      83c454         add esp, 0x54
│           0x01015a6e      33d2           xor edx, edx
│           0x01015a70      648f02         pop dword fs:[edx]
│           0x01015a73      5a             pop edx
│           0x01015a74      68618a0001     push 0x1008a61
└           0x01015a79      c3             ret
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: missing — Data Execution Prevention flag not set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 54
  wcscat @ 0x100d1f8 (fcn.0100cf7d)
  wcscat @ 0x100d29b (fcn.0100d259)
  swprintf @ 0x101105b (fcn.01011037)
  swprintf @ 0x10114f0 (fcn.010114ca)
  swprintf @ 0x1011610 (fcn.010115ea)
  swprintf @ 0x1011795 (?)
  swprintf @ 0x1011956 (?)
  swprintf @ 0x1011b0c (?)
  swprintf @ 0x1011c13 (?)
  swprintf @ 0x1011e49 (?)
  swprintf @ 0x10120a2 (?)
  swprintf @ 0x10126b7 (?)
  swprintf @ 0x1012d02 (?)
  wcscpy @ 0x100d20a (fcn.0100cf7d)
  wcscpy @ 0x100d2ab (fcn.0100d259)

## revai_tools_audit (pe, revai_tools_audit)

<!-- evidence_assembler: used 15145/60000 chars across 12 tools -->