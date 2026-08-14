## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=bf0d6cc20fa7a20e | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=121, sha256=bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76
  Anomalies (11): BigStringHiScore (strings), DynamicString (strings), EmbeddedProgram (embedding), HugeStringBinary (strings), InvalidChecksum (integrity), ManyUniqueImmediateBytes (code), PossiblePackerApiDynamicImport (imports), SpaghettiFunction (code), StackArrayInitialisationX86×2 (code), StringBase64 (strings), XorInLoop×5 (code)
  High-signal anomaly locations: DynamicString@3735; ManyUniqueImmediateBytes@11347; SpaghettiFunction@11347; XorInLoop@1111,1832,2260
  YARA (signal): ChangeBrowserPreference
  YARA (info, 7 total): MSVC_2008_linker, MSVC_2008_rich, CustomUserAgent, EnumerateProcesses, AutorunKey, ElevatePrivileges, RunShell
  Functions (15): sub_100019a0@3488, sub_100045b2@14770, sub_100015a0@2464, sub_100010f0@1264, sub_100013e0@2016, sub_10001e80@4736, sub_10002300@5888, sub_100026a0@6816, sub_10003853@11347, sub_1000376a@11114, sub_100036b9@10937, sub_1000292a@7466, sub_10002d4c@8524, sub_10001000@1024, sub_10001820@3104
  Top high-signal imports (score≥8, 7 of 88):
    [10] kernel32.CreateRemoteThread ×2
    [10] kernel32.VirtualAllocEx ×2
    [10] kernel32.WriteProcessMemory ×2
    [8] kernel32.VirtualProtectEx ×4
    [8] advapi32.AdjustTokenPrivileges
    [8] advapi32.LookupPrivilegeValueA
    [8] kernel32.CreateToolhelp32Snapshot
  Mid-signal imports: advapi32.OpenProcessToken, kernel32.CreateProcessA, kernel32.OpenProcess, kernel32.QueryPerformanceCounter, kernel32.TerminateProcess, kernel32.GetProcAddress, kernel32.DeleteFileA, kernel32.LoadLibraryA, kernel32.CreateFileA, kernel32.GetModuleHandleA, advapi32.RegOpenKeyExA
  (low-signal/noise imports: 70 omitted)
  * Constants/registry (2): registry::HKEY_CURRENT_USER, registry::autorun×3
  * Constants/crypto (2): crypto::Base64, crypto::ASCII_to_BIN_table__8_byt_128
    Constants/exception (1): exception::C++ exception
    Constants/hash (1): hash::Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640
  Strings/registry (4 total): Software\Microso..rrentVersion\Run, Software\Microso..nternet Settings
  Strings/mutex (1 total): Global\{7BDACDEE..46-D00FCFF1FFBA}
  Strings/suspicious (1 total): cmd.exe /c %s > %s
  Strings/apis (41 total): LoadLibraryA, FreeLibrary, LoadResource, OriginalFilename, GetSystemTimeAsFileTime, FileDescription, SetUnhandledExceptionFilter, StringFileInfo, QueryPerformanceCounter, FileVersion, CreateRemoteThread, GetFileInformationByHandle, WriteProcessMemory, GetCurrentProcess, GetCurrentThreadId
  Strings (other, 253 items, omitted)
  Carved files (1): PE@29960 (52736 bytes)
  Virtual files (3): ASDASDASDASDSAD/102/en-us, VER/1/en-us, MANIF/2/en-us
  Recovered structures (42): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, kernel32.FT, rpcrt4.FT, shell32.FT, msvcrt.FT, ole32.FT, LoadConfigurationTable, SEHandlers, ImportTable, advapi32.OFT
  Decompilations (3 top functions):
    ### 3488 (sub_100019a0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_100019a0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
    int32_t iVar1;
    undefined4 uVar2;
    int32_t iVar3;
    undefined4 *puVar4;
    undefined4 *puVar5;
    undefined4 uStack_5bc;
    undefined4 uStack_5b8;
    undefined4 uStack_5b4;
    undefined auStack_5b0 [24];
    undefined4 uStack_598;
    undefined auStack_594 [520];
    undefined4 uStack_38c;
    undefined auStack_388 [4];
    undefined4 uStack_384;
    int32_t iStack_260;
    undefined4 auStack_25c [11];
    undefined auStack_22e [222];
    int32_t iStack_150;
    undefined4 uStack_14c;
    undefined auStack_148 [8];
    undefined4 uStack_140;
    int32_t iStack_13c;
    int32_t iStack_138;
    undefined4 uStack_134;
    undefined4 uStack_130;
    int32_t iStack_12c;
    undefined4 uStack_128;
    undefined4 uStack_124;
    int32_t iStack_120;
    undefined4 uStack_11c;
    undefined4 uStack_118;
    undefined auStack_114 [268];
    uint32_t uStack_8;
    
    uStack_8 = [0x0x10007000#SecurityCookie] ^ &stack0xfffffffc;
    sub_100026a0("Removing...");
    (*kernel32.Sleep)(1000);
    iVar1 = (*shell32.SHGetSpecialFolderPathA)(0, auStack_114, 0x1a, 0);
    if (iVar1 != 0) {
        _strcat_s(auStack_114, 0x104, "\\LocalData\\");
        (*kernel32.RemoveDirectoryA)(auStack_114);
        (*kernel32.CreateDirectoryA)(auStack_114, 0);
        uStack_124 = 0;
        puVar4 = &autorun;
        puVar5 = auStack_25c;
        for (iVar1 = 0xb; iVar1 != 0; iVar1 = iVar1 + -1) {
            *puVar5 = *puVar4;
            puVar4 = puVar4 + 1;
            puVar5 = puVar5 + 1;
        }
        *puVar5 = *puVar4;
        jmp_msvcrt.memset(auStack_22e, 0, 0xd6);
        iVar1 = (*advapi32.RegOpenKeyExA)(0x80000001, auStack_25c, 0, 2, &uStack_124);
        if (iVar1 == 0) {
            (*advapi32.RegDeleteValueA)(uStack_124, "SystemDrive");
            (*advapi32.RegCloseKey)(uStack_124);
            uStack_11c = 0;
            uSt
```
    ### 14770 (sub_100045b2, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_100045b2(void)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uStack_14;
    uint32_t uStack_10;
    uint32_t uStack_c;
    uint32_t uStack_8;
    
    uStack_c = 0;
    uStack_8 = 0;
    if (([0x0x10007000#SecurityCookie] == 0xbb40e64e) || (([0x0x10007000#SecurityCookie] & 0xffff0000) == 0)) {
        (*kernel32.GetSystemTimeAsFileTime)(&uStack_c);
        uVar4 = uStack_8 ^ uStack_c;
        uVar1 = (*kernel32.GetCurrentProcessId)();
        uVar2 = (*kernel32.GetCurrentThreadId)();
        uVar3 = (*kernel32.GetTickCount)();
        (*kernel32.QueryPerformanceCounter)(&uStack_14);
        uVar1 = uVar4 ^ uVar1 ^ uVar2 ^ uVar3 ^ uStack_10 ^ uStack_14;
        if ((uVar1 == 0xbb40e64e) || (([0x0x10007000#SecurityCookie] & 0xffff0000) == 0)) {
            uVar1 = 0xbb40e64f;
        }
        10007004 = ~uVar1;
        10007000 = uVar1;
    }
    else {
        10007004 = ~[0x0x10007000#SecurityCookie];
    }
    return;
}
```
    ### 2464 (sub_100015a0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_100015a0(undefined4 *param_1)

{
    uint8_t uVar1;
    uint32_t uVar2;
    int32_t iVar3;
    undefined4 *puVar4;
    uint32_t uStack_1b0;
    undefined uStack_1ac;
    undefined auStack_1ab [267];
    uint8_t *puStack_a0;
    undefined4 uStack_9c;
    int32_t iStack_98;
    undefined4 uStack_94;
    undefined auStack_90 [136];
    uint32_t uStack_8;
    
    uStack_8 = [0x0x10007000#SecurityCookie] ^ &stack0xfffffffc;
    uStack_94 = 0;
    jmp_msvcrt.memset(auStack_90, 0, 0x80);
    if (param_1 != 0x0) {
        puVar4 = &uStack_94;
        for (iVar3 = 0x21; iVar3 != 0; iVar3 = iVar3 + -1) {
            *puVar4 = *param_1;
            param_1 = param_1 + 1;
            puVar4 = puVar4 + 1;
        }
    }
    (*msvcrt.srand)(0xa03);
    for (uStack_1b0 = 0; uStack_1b0 < 0x84; uStack_1b0 = uStack_1b0 + 1) {
        puStack_a0 = auStack_90 + (uStack_1b0 - 4);
        uVar1 = *puStack_a0;
        uVar2 = (*msvcrt.rand)();
        uVar2 = uVar2 & 0x8000007f;
        if (uVar2 < 0) {
            uVar2 = (uVar2 - 1 | 0xffffff80) + 1;
        }
        *puStack_a0 = uVar1 ^ uVar2;
    }
    uStack_1ac = 0;
    jmp_msvcrt.memset(auStack_1ab, 0, 0x103);
    sub_100010a0(&uStack_1ac, 0x104);
    uStack_9c = 0;
    iStack_98 = (*kernel32.CreateFileA)(&uStack_1ac, 0x40000000, 0, 0, 4, 0, 0);
    if (iStack_98 != -1) {
        (*kernel32.SetFilePointer)(iStack_98, 0x488, 0, 0);
        (*kernel32.WriteFile)(iStack_98, &uStack_94, 0x84, &uStack_9c, 0);
        (*kernel32.CloseHandle)(iStack_98);
    }
    @__security_check_cookie@4();
    return;
}
```

## capa evidence (30 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (3): get common file path, get file size, get Program Files directory
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): reference Base64 string
  ATT&CK {'parts': ['Defense Evasion', 'Process Injection', 'Thread Execution Hijacking'], 'tactic': 'Defense Evasion', 'technique': 'Process Injection', 'subtechnique': 'Thread Execution Hijacking', 'id': 'T1055.003'} (1): inject thread
  ATT&CK {'parts': ['Defense Evasion', 'Reflective Code Loading'], 'tactic': 'Defense Evasion', 'technique': 'Reflective Code Loading', 'subtechnique': '', 'id': 'T1620'} (1): inject thread
  ATT&CK {'parts': ['Discovery', 'Process Discovery'], 'tactic': 'Discovery', 'technique': 'Process Discovery', 'subtechnique': '', 'id': 'T1057'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Software Discovery'], 'tactic': 'Discovery', 'technique': 'Software Discovery', 'subtechnique': '', 'id': 'T1518'} (1): enumerate processes
  ATT&CK {'parts': ['Defense Evasion', 'Modify Registry'], 'tactic': 'Defense Evasion', 'technique': 'Modify Registry', 'subtechnique': '', 'id': 'T1112'} (1): delete registry value
  ATT&CK {'parts': ['Persistence', 'Boot or Logon Autostart Execution', 'Registry Run Keys / Startup Folder'], 'tactic': 'Persistence', 'technique': 'Boot or Logon Autostart Execution', 'subtechnique': 'Registry Run Keys / Startup Folder', 'id': 'T1547.001'} (1): persist via Run registry key
  All rules (6): spawn thread to RWX shellcode, contain an embedded PE file, copy file, create directory, delete directory, delete file

## pe_imports (88 imports, 7 high-signal)
  allocate_memory (VirtualAllocEx) [T1055]
  write_process_memory (WriteProcessMemory) [T1055]
  create_remote_thread (CreateRemoteThread) [T1055]
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]

## YARA matches (26)
  Rules: domain, IP, contains_base64, System_Tools, Dropper_Strings, Misc_Suspicious_Strings, SHA512_Constants, BASE64_table, Emissary_APT_Malware_1, IsPE32, IsDLL, IsWindowsGUI, HasRichSignature, Visual_Cpp_2005_DLL_Microsoft, Visual_Cpp_2003_DLL_Microsoft, SEH_Save, SEH_Init, Check_OutputDebugStringA_iat, anti_dbg, inject_thread, escalate_priv, win_mutex, win_registry, win_token, win_files_operation

## FLOSS strings (619 total)
  registry (2): Software\Microsoft\Windows\CurrentVersion\Run, Software\Microsoft\Windows\CurrentVersion\Internet Settings
  suspicious (1): rundll32.exe "%s",Setting
  apis (3): LoadResource, FreeLibrary, LoadLibraryA
  (other strings, 74 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 3 functions (asm)
  ### 0x10003477
```c
┌ 400: entry0 (int32_t arg_8h, int32_t arg_ch, int32_t arg_10h);
│       ╎   ; arg int32_t arg_8h @ ebp+0x8
│       ╎   ; arg int32_t arg_ch @ ebp+0xc
│       ╎   ; arg int32_t arg_10h @ ebp+0x10
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   0x10003477      8bff           mov edi, edi
│       ╎   0x10003479      55             push ebp
│       ╎   0x1000347a      8bec           mov ebp, esp
│       ╎   0x1000347c      837d0c01       cmp dword [arg_ch], 1
│      ┌──< 0x10003480      7505           jne 0x10003487
│      │╎   0x10003482      e82b110000     call 0x100045b2
│      └──> 0x10003487      5d             pop ebp
│       └─< 0x10003488      e98efdffff     jmp 0x1000321b
..
            ; XREFS: CALL 0x10002328  CALL 0x10002345  CALL 0x1000235f  
            ; XREFS: CALL 0x1000237c  CALL 0x10002399  CALL 0x100023b8  
            ; XREFS: CALL 0x100023d5  CALL 0x100025d2  
```
  ### 0x10002660
```c
┌ 10: sym.Loader.dll_Setting ();
│           0x10002660      55             push ebp
│           0x10002661      8bec           mov ebp, esp
│           0x10002663      e898fcffff     call fcn.10002300
│           0x10002668      5d             pop ebp
└           0x10002669      c3             ret
```
  ### 0x10002300
```c
; CALL XREF from sym.Loader.dll_Setting @ 0x10002663(x)
┌ 852: fcn.10002300 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_20eh @ ebp-0x20e
│           ; var int32_t var_210h @ ebp-0x210
│           ; var int32_t var_317h @ ebp-0x317
│           ; var int32_t var_318h @ ebp-0x318
│           ; var int32_t var_31ch @ ebp-0x31c
│           ; var int32_t var_427h @ ebp-0x427
│           ; var int32_t var_428h @ ebp-0x428
│           ; var int32_t var_52fh @ ebp-0x52f
│           ; var int32_t var_530h @ ebp-0x530
│           ; var int32_t var_637h @ ebp-0x637
│           ; var int32_t var_638h @ ebp-0x638
│           ; var int32_t var_72eh @ ebp-0x72e
│           ; var int32_t var_730h @ ebp-0x730
│           ; var int32_t var_734h @ ebp-0x734
│           ; var int32_t var_738h @ ebp-0x738
│           ; var int32_t var_73ch @ ebp-0x73c
│           ; var int32_t var_73fh @ ebp-0x73f
│           ; var int32_t var_740h @ ebp-0x740
│           ; var int32_t var_773h @ ebp-0x773
│           ; var int32_t var_774h @ ebp-0x774
│           ; var int32_t var_7fch @ ebp-0x7fc
│           ; var int32_t var_800h @ ebp-0x800
│           ; var int32_t var_810h @ ebp-0x810
│           ; var int32_t var_814h @ ebp-0x814
│           0x10002300      55             push ebp
│           0x10002301      8bec           mov ebp, esp
│           0x10002303      81ec14080000   sub esp, 0x814
│           0x10002309      a100700010     mov eax, dword [section..data] ; [0x10007000:4]=0xbb40e64e ; "N\xe6@\xbb\xb1\x19\xbfD"
│           0x1000230e      33c5           xor eax, ebp
│           0x10002310      8945fc         mov dword [var_4h], eax
│           0x10002313      c685c8f9ff..   mov byte [var_638h], 0
│           0x1000231a      6803010000     push 0x103                  ; 259
│           0x1000231f      6a00           push 0
│           0x10002321      8d85c9f9ffff   lea eax, [var_637h]
│           0x10002327      50             push eax
│           0x10002328      e8d9120000     call 0x10003606
│           0x1000232d      83c40c         add esp, 0xc
│           0x10002330      c685d8fbff..   mov byte [var_428h], 0
│           0x10002337      6803010000     push 0x103                  ; 259
│           0x1000233c      6a00           push 0
│           0x1000233e      8d8dd9fbffff   lea ecx, [var_427h]
│           0x10002344      51             push ecx
│           0x10002345      e8bc120000     call 0x10003606
│           0x1000234a      83c40c      
```

## UPX
  (not packed)


## xorsearch (2 candidates)
  Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r
  Found XOR 00 position 00005908: 00000110 ........!..L.!This program cannot be r

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: present — Data Execution Prevention flag set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 12
  memcpy @ 0x1000360c (sub.msvcrt.dll_memcpy)
  malloc @ 0x10003077 (?)
  malloc @ 0x10003e8b (fcn.10003853)
  rand @ 0x10001045 (fcn.10001000)
  rand @ 0x10001316 (fcn.100010f0)
  rand @ 0x100014c2 (fcn.100013e0)
  rand @ 0x1000163d (fcn.100015a0)
  srand @ 0x1000100c (fcn.10001000)
  srand @ 0x100012ca (fcn.100010f0)
  srand @ 0x10001480 (fcn.100013e0)
  srand @ 0x100015f1 (fcn.100015a0)
  createprocessa @ 0x10001feb (fcn.10001e80)

## revai_tools_audit (pe, revai_tools_audit)

<!-- evidence_assembler: used 16248/60000 chars across 12 tools -->