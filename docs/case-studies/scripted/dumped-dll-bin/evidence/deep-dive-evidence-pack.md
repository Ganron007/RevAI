## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=a2923d838f2d301a | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=120, sha256=a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395
  Anomalies (11): BigStringHiScore×5 (strings), CryptoApiUsage×2 (imports), DynamicString×10 (strings), HighXrefLoopingFunction×8 (code), ManyHighValueImmediates×9 (code), ManyUniqueImmediateBytes×3 (code), NoChecksum (integrity), SequentialFunction×64 (code), SpaghettiFunction×26 (code), StackArrayInitialisationX64×8 (code), XorInLoop×89 (code)
  High-signal anomaly locations: CryptoApiUsage@257841,257153; DynamicString@550465,552516,557043; HighXrefLoopingFunction@301140,309856,310400; ManyHighValueImmediates@272640,283184,295328; ManyUniqueImmediateBytes@9008,364392,552492; NoChecksum@376; SequentialFunction@27744,49760,51184; SpaghettiFunction@29072,230416,231856; XorInLoop@46000,46404,46896
  YARA (signal): MiningProtocol
  YARA (info, 4 total): MSVC_2017_linker, visual_studio_2017_version_15_7_1_rich, visual_studio_2017_version_15_6_6_rich, ElevatePrivileges
  Functions (15): sub_1800323c0@202688, #17@60304, sub_180020950@130384, sub_18002cba0@180128, #27@84560, sub_18001b8b0@109744, sub_180026810@154640, sub_18001f920@126240, #16@56160, sub_18002b810@175120, #26@79616, sub_1800254c0@149696, sub_18001a560@104800, sub_18002a950@171344, sub_180030550@194896
  Top high-signal imports (score≥8, 9 of 187):
    [10] advapi32.CryptAcquireContextA ×6
    [10] kernel32.IsDebuggerPresent ×2
    [10] advapi32.CryptGenRandom
    [10] advapi32.CryptReleaseContext
    [9] ws2_32.WSAStartup
    [8] kernel32.VirtualAlloc ×2
    [8] advapi32.AdjustTokenPrivileges
    [8] advapi32.LookupPrivilegeValueW
    [8] kernel32.ConnectNamedPipe
  Mid-signal imports: kernel32.QueryPerformanceCounter, advapi32.OpenProcessToken, kernel32.TerminateProcess, ws2_32.WSARecv, kernel32.CreateThread, ws2_32.WSARecvFrom, ws2_32.WSASend, kernel32.GetProcAddress, kernel32.LoadLibraryExW, kernel32.LoadLibraryA, kernel32.CreateNamedPipeW, kernel32.CreateFileW, kernel32.GetModuleHandleW, kernel32.CreateFileA, kernel32.DuplicateHandle, kernel32.GetModuleHandleA, kernel32.GetModuleHandleExW
  (low-signal/noise imports: 161 omitted)
  * Constants/registry (3): registry::HKEY_LOCAL_MACHINE, registry::HKEY_USERS×2, registry::HKEY_CURRENT_USER×2
  * Constants/crypto (1): crypto::AES×5
    Constants/exception (3): exception::FuncInfo header, exception::C++ exception, exception::CLR exception
    Constants/code (1): code::PEBx64
    Constants/math (1): math::log10
  Strings/ips (1 total): 0.0.0.0
  Strings/paths (1 total): """"""""""""""""\\\\\\\\\\\\\\\\
  Strings/apis (46 total): SeLockMemoryPrivilege, GetCurrentProcessorNumber, NtQueryVolumeInformationFile, InitOnceExecuteOnce, WaitForThreadpoolTimerCallbacks, FreeLibraryWhenCallbackReturns, FlushProcessWriteBuffers, GetQueuedCompletionStatus, SetFileInformationByHandle, GetFileInformationByHandleEx, CreateThreadpoolTimer, CreateThreadpoolWork, NtQuerySystemInformation, NtQueryDirectoryFile, GetFinalPathNameByHandleW
  Strings (other, 252 items, omitted)
  Carved files (4): PNG@722400 (6395 bytes), DIB@728800 (9640 bytes), DIB@738440 (4264 bytes), DIB@742704 (1128 bytes)
  Virtual files (7): ICO/1/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, GRPICO/IDI_ICON1/en-us, VER/1/en-us, MANIF/2/en-us
  Recovered structures (58): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, kernel32.FT, user32.FT, ws2_32.FT, GuardCFCheckFunctionPointer, GuardCFDispatchFunctionPointer, TlsCallbacks, DebugDirectory, LoadConfigurationTable, TlsDirectory
  Decompilations (3 top functions):
    ### 202688 (sub_1800323c0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_1800323c0(int64_t param_1,uint64_t param_2,int64_t param_3,uint64_t **param_4)

{
    undefined auVar1 [16];
    undefined auVar2 [16];
    undefined auVar3 [16];
    undefined auVar4 [16];
    undefined auVar5 [16];
    uint64_t uVar6;
    uint64_t uVar7;
    uint64_t uVar8;
    uint64_t uVar9;
    undefined auVar10 [16];
    undefined auVar11 [16];
    undefined auVar12 [16];
    undefined auVar13 [16];
    undefined auVar14 [16];
    undefined auVar15 [16];
    undefined auVar16 [16];
    undefined auVar17 [16];
    undefined auVar18 [16];
    undefined auVar19 [16];
    undefined auVar20 [16];
    undefined auVar21 [16];
    undefined auVar22 [16];
    undefined auVar23 [16];
    undefined auVar24 [16];
    uint64_t uVar25;
    uint64_t uVar26;
    uint64_t uVar27;
    uint64_t uVar28;
    uint64_t uVar29;
    uint64_t uVar30;
    uint64_t uVar31;
    uint64_t uVar32;
    undefined (*pauVar33) [16];
    uint64_t *puVar34;
    uint64_t uVar35;
    uint64_t uVar36;
    uint64_t uVar37;
    uint64_t uVar38;
    uint64_t uVar39;
    uint64_t uVar40;
    uint64_t uVar41;
    uint64_t uVar42;
    uint32_t uVar43;
    uint32_t uVar44;
    undefined (*pauVar45) [16];
    undefined (*pauVar46) [16];
    uint64_t *puVar47;
    uint64_t uVar48;
    uint64_t uVar49;
    uint32_t uVar50;
    uint32_t uVar51;
    uint64_t *puVar52;
    undefined (*pauVar53) [16];
    uint64_t *puVar54;
    uint64_t *puVar55;
    undefined auVar56 [16];
    uint64_t uVar57;
    uint64_t uVar58;
    uint64_t uVar59;
    uint64_t uVar60;
    uint64_t uVar61;
    uint64_t uVar62;
    uint64_t uVar63;
    uint32_t uVar67;
    uint64_t uVar64;
    uint64_t uVar65;
    uint64_t uVar66;
    uint32_t uVar69;
    uint32_t uVar70;
    uint32_t uVar71;
    undefined auVar68 [16];
    uint32_t uVar73;
    uint32_t uVar74;
    undefined auVar72 [16];
    undefined auVar75 [16];
    undefined auVar76 [16];
    undefined auVar77 [16];
    uint
```
    ### 60304 (#17, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void xmrig::CpuThread.#17(int64_t param_1,uint64_t param_2,int64_t param_3,uint64_t **param_4)

{
    undefined auVar1 [16];
    undefined auVar2 [16];
    undefined auVar3 [16];
    undefined auVar4 [16];
    undefined auVar5 [16];
    uint64_t *puVar6;
    uint64_t *puVar7;
    uint64_t *puVar8;
    uint64_t uVar9;
    uint64_t uVar10;
    uint64_t uVar11;
    uint64_t uVar12;
    undefined auVar13 [16];
    undefined auVar14 [16];
    undefined auVar15 [16];
    undefined auVar16 [16];
    undefined auVar17 [16];
    undefined auVar18 [16];
    undefined auVar19 [16];
    undefined auVar20 [16];
    undefined auVar21 [16];
    undefined auVar22 [16];
    undefined auVar23 [16];
    undefined auVar24 [16];
    undefined auVar25 [16];
    undefined auVar26 [16];
    undefined auVar27 [16];
    uint64_t uVar28;
    uint64_t uVar29;
    uint64_t uVar30;
    uint64_t uVar31;
    uint64_t uVar32;
    uint64_t uVar33;
    uint64_t uVar34;
    uint64_t uVar35;
    uint64_t uVar36;
    uint64_t uVar37;
    uint64_t uVar38;
    uint64_t uVar39;
    uint64_t uVar40;
    uint64_t uVar41;
    uint64_t uVar42;
    uint64_t uVar43;
    undefined (*pauVar44) [16];
    uint32_t uVar45;
    uint32_t uVar46;
    uint32_t uVar47;
    uint32_t uVar48;
    uint64_t uVar49;
    uint64_t uVar50;
    undefined (*pauVar51) [16];
    uint64_t uVar52;
    uint32_t uVar53;
    uint32_t uVar54;
    undefined (*pauVar55) [16];
    undefined (*pauVar56) [16];
    uint64_t uVar57;
    undefined (*pauVar58) [16];
    uint64_t *puVar59;
    uint64_t *puVar60;
    undefined auVar61 [16];
    uint64_t uVar62;
    uint64_t uVar63;
    uint64_t uVar64;
    uint64_t uVar65;
    uint64_t uVar66;
    uint64_t uVar67;
    uint64_t uVar68;
    uint64_t uVar69;
    uint64_t uVar70;
    uint64_t uVar71;
    uint32_t uVar73;
    uint32_t uVar74;
    undefined auVar72 [16];
    uint32_t uVar76;
    uint32_t uVar77;
    undefined auVar75 [16];
    uint32_
```
    ### 130384 (sub_180020950, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_180020950(int64_t param_1,uint64_t param_2,int64_t param_3,uint64_t **param_4)

{
    undefined auVar1 [16];
    undefined auVar2 [16];
    undefined auVar3 [16];
    undefined auVar4 [16];
    undefined auVar5 [16];
    uint64_t *puVar6;
    uint64_t *puVar7;
    uint64_t *puVar8;
    uint64_t uVar9;
    uint64_t uVar10;
    uint64_t uVar11;
    uint64_t uVar12;
    undefined auVar13 [16];
    undefined auVar14 [16];
    undefined auVar15 [16];
    undefined auVar16 [16];
    undefined auVar17 [16];
    undefined auVar18 [16];
    undefined auVar19 [16];
    undefined auVar20 [16];
    undefined auVar21 [16];
    undefined auVar22 [16];
    undefined auVar23 [16];
    undefined auVar24 [16];
    undefined auVar25 [16];
    undefined auVar26 [16];
    undefined auVar27 [16];
    uint64_t uVar28;
    uint64_t uVar29;
    uint64_t uVar30;
    uint64_t uVar31;
    uint64_t uVar32;
    uint64_t uVar33;
    uint64_t uVar34;
    uint64_t uVar35;
    uint64_t uVar36;
    uint64_t uVar37;
    uint64_t uVar38;
    uint64_t uVar39;
    uint64_t uVar40;
    uint64_t uVar41;
    uint64_t uVar42;
    uint64_t uVar43;
    undefined (*pauVar44) [16];
    uint32_t uVar45;
    uint32_t uVar46;
    uint32_t uVar47;
    uint32_t uVar48;
    uint64_t uVar49;
    uint64_t uVar50;
    undefined (*pauVar51) [16];
    uint64_t uVar52;
    uint32_t uVar53;
    uint32_t uVar54;
    undefined (*pauVar55) [16];
    undefined (*pauVar56) [16];
    uint64_t uVar57;
    undefined (*pauVar58) [16];
    uint64_t *puVar59;
    uint64_t *puVar60;
    undefined auVar61 [16];
    uint64_t uVar62;
    uint64_t uVar63;
    uint64_t uVar64;
    uint64_t uVar65;
    uint64_t uVar66;
    uint64_t uVar67;
    uint64_t uVar68;
    uint64_t uVar69;
    uint64_t uVar70;
    uint64_t uVar71;
    uint32_t uVar73;
    uint32_t uVar74;
    undefined auVar72 [16];
    uint32_t uVar76;
    uint32_t uVar77;
    undefined auVar75 [16];
    uint32_t uVar7
```

## capa evidence (43 total, showing top 15)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (4): encode data using XOR, encrypt data using AES, encrypt data using AES via x86 extensions, encrypt data using speck
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (2): get common file path, check if file exists
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Discovery', 'System Network Configuration Discovery'], 'tactic': 'Discovery', 'technique': 'System Network Configuration Discovery', 'subtechnique': '', 'id': 'T1016'} (1): get socket status
  ATT&CK {'parts': ['Collection', 'Input Capture', 'Keylogging'], 'tactic': 'Collection', 'technique': 'Input Capture', 'subtechnique': 'Keylogging', 'id': 'T1056.001'} (1): log keystrokes
  All rules (6): check for time delay via QueryPerformanceCounter, receive data, send data, resolve DNS, connect pipe, create pipe

## pe_imports (187 imports, 4 high-signal)
  check_debugger (IsDebuggerPresent) [T1622]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (23)
  Rules: domain, IP, contains_base64, SHA2_BLAKE2_IVs, RijnDael_AES_CHAR, SHA3_constants, IsPE64, IsDLL, IsConsole, HasDebugData, HasRichSignature, DebuggerException__SetConsoleCtrl, anti_dbg, network_udp_sock, network_tcp_listen, network_tcp_socket, network_dns, escalate_priv, keylogger, win_token, win_files_operation, Str_Win32_Winsock2_Library, XMRIG_Miner

## FLOSS strings (2082 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 4 functions (asm)
  ### 0x18004afe0
```c
┌ 362: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg_78h);
│      ╎╎   ; arg int64_t arg1 @ rcx
│      ╎╎   ; arg int64_t arg2 @ rdx
│      ╎╎   ; arg int64_t arg3 @ r8
│      ╎╎   ; arg int64_t arg_78h @ rsp+0xd8
│      ╎╎   ; var int64_t var_30h @ rsp+0x30
│      ╎╎   ; var int64_t var_8h @ rsp+0x60
│      ╎╎   ; var int64_t var_10h @ rsp+0x68
│      ╎╎   0x18004afe0      48895c2408     mov qword [var_8h], rbx
│      ╎╎   0x18004afe5      4889742410     mov qword [var_10h], rsi
│      ╎╎   0x18004afea      57             push rdi
│      ╎╎   0x18004afeb      4883ec20       sub rsp, 0x20
│      ╎╎   0x18004afef      498bf8         mov rdi, r8                ; arg3
│      ╎╎   0x18004aff2      8bda           mov ebx, edx               ; arg2
│      ╎╎   0x18004aff4      488bf1         mov rsi, rcx               ; arg1
│      ╎╎   0x18004aff7      83fa01         cmp edx, 1                 ; 1 ; arg2
│     ┌───< 0x18004affa      7505           jne 0x18004b001
│     │╎╎   0x18004affc      e867040000     call 0x18004b468
│     └───> 0x18004b001      4c8bc7         mov r8, rdi
│      ╎╎   0x18004b004      8bd3           mov edx, ebx
│      ╎╎   0x18004b006      488bce         mov rcx, rsi
│      ╎╎   0x18004b009      488b5c2430     mov rbx, qword [var_8h]
│      ╎╎   0x18004b00e      488b742438     mov rsi, qword [var_10h]
│      ╎╎   0x18004b013      4883c420       add rsp, 0x20
│      ╎╎   0x18004b017      5f             pop rdi
│      └──< 0x18004b018      e98ffeffff     jmp 0x18004aeac
..
│           ; CODE XREF from fcn.18004a490 @ 0x18004a490(x)
```
  ### 0x18007f630
```c
┌ 103: sym.xmrig.dll_Start (int64_t arg2);
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_20h @ rsp+0x20
│           ; var int64_t var_30h @ rsp+0x30
│           ; var int64_t var_38h @ rsp+0x38
│           ; var int64_t var_360h @ rsp+0x360
│           0x18007f630      4053           push rbx
│           0x18007f632      4881ec7003..   sub rsp, 0x370
│           0x18007f639      48c7442420..   mov qword [var_20h], 0xfffffffffffffffe
│           0x18007f642      488d4c2430     lea rcx, [var_30h]
│           0x18007f647      e8045cfeff     call fcn.180065250
│           0x18007f64c      488d4c2430     lea rcx, [var_30h]
│           0x18007f651      e87a58feff     call fcn.180064ed0
│           0x18007f656      8bd8           mov ebx, eax
│           0x18007f658      488d0571b7..   lea rax, [0x18009add0]
│           0x18007f65f      4889442430     mov qword [var_30h], rax
│           0x18007f664      ba68010000     mov edx, 0x168             ; 360
│           0x18007f669      488b4c2438     mov rcx, qword [var_38h]
│           0x18007f66e      e81daefcff     call fcn.18004a490
│           0x18007f673      488b8c2460..   mov rcx, qword [var_360h]
│           0x18007f67b      4885c9         test rcx, rcx
│       ┌─< 0x18007f67e      740c           je 0x18007f68c
│       │   0x18007f680      4c8b01         mov r8, qword [rcx]
│       │   0x18007f683      ba01000000     mov edx, 1
│       │   0x18007f688      41ff10         call qword [r8]
│       │   0x18007f68b      90             nop
│       └─> 0x18007f68c      8bc3           mov eax, ebx
│           0x18007f68e      4881c47003..   add rsp, 0x370
│           0x18007f695      5b             pop rbx
└           0x18007f696      c3             ret
```
  ### 0x180065250
```c
; CALL XREF from sym.xmrig.dll_Start @ 0x18007f647(x)
┌ 742: fcn.180065250 (int64_t arg1, int64_t arg3);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg3 @ r8
│           ; var int64_t var_28h @ rbp+0x28
│           ; var int64_t var_10h @ rbp+0x10
│           ; var int64_t var_20h @ rsp+0x20
│           ; var int64_t var_8h @ rsp+0x50
│           ; var int64_t var_58h @ rsp+0x58
│           ; var int64_t var_18h @ rsp+0x60
│           ; var int64_t var_68h @ rsp+0x68
│           0x180065250      4c89442418     mov qword [var_18h], r8    ; arg3
│           0x180065255      48894c2408     mov qword [var_8h], rcx    ; arg1
│           0x18006525a      56             push rsi
│           0x18006525b      57             push rdi
│           0x18006525c      4156           push r14
│           0x18006525e      4883ec30       sub rsp, 0x30
│           0x180065262      48c7442420..   mov qword [var_20h], 0xfffffffffffffffe
│           0x18006526b      48895c2458     mov qword [var_58h], rbx
│           0x180065270      48896c2468     mov qword [var_68h], rbp
│           0x180065275      488bf9         mov rdi, rcx               ; arg1
│           0x180065278      488d05515b..   lea rax, [0x18009add0]
│           0x18006527f      488901         mov qword [rcx], rax       ; arg1
│           0x180065282      33ed           xor ebp, ebp
│           0x180065284      48896908       mov qword [rcx + 8], rbp   ; arg1
│           0x180065288      48896910       mov qword [rcx + 0x10], rbp ; arg1
│           0x18006528c      48890ded5f..   mov qword [0x1800ab280], rcx ; [0x1800ab280:8]=0 ; arg1
│           0x180065293      8d4d10         lea ecx, [var_10h]
│           0x180065296      e8b951feff     call 0x18004a454
│           0x18006529b      488bd8         mov rbx, rax
│           0x18006529e      4889442460     mov qword [var_18h], rax
│           0x1800652a3      488d054e71..   lea rax, [0x18009c3f8]
│           0x1800652aa      488903         mov qword [rbx], rax
│           0x1800652ad      8d4d28         lea ecx, [var_28h]
│           0x1800652b0      e89f51feff     call 0x18004a454
│           0x1800652b5      4889442460     mov qword [var_18h], rax
│           0x1800652ba      488928         mov qword [rax], rbp
│           0x1800652bd      48896808       mov qword [rax + 8], rbp
│           0x1800652c1      48896810       mov qword [rax + 0x10], rbp
│           0x1800652c5      48896818       mov qword [rax + 0x18], rbp
│           0x1800652c9
```
  ### 0x180064ed0
```c
; CALL XREF from sym.xmrig.dll_Start @ 0x18007f651(x)
┌ 785: fcn.180064ed0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_28h @ rbp+0x28
│           ; var int64_t var_20h @ rbp+0x20
│           ; var int64_t var_18h @ rbp+0x18
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_18h_2 @ rbp-0x18
│           ; var int64_t var_20h_2 @ rbp-0x20
│           ; var int64_t var_28h_2 @ rbp-0x28
│           ; var int64_t var_30h @ rbp-0x30
│           ; var int64_t var_38h @ rbp-0x38
│           ; var int64_t var_40h @ rbp-0x40
│           ; var int64_t var_48h @ rbp-0x48
│           ; var int64_t var_sp_20h @ rsp+0x20
│           ; var int64_t var_70h @ rsp+0x70
│           ; var int64_t var_a8h @ rsp+0xa8
│           0x180064ed0      4055           push rbp
│           0x180064ed2      53             push rbx
│           0x180064ed3      488bec         mov rbp, rsp
│           0x180064ed6      4883ec78       sub rsp, 0x78
│           0x180064eda      488b813003..   mov rax, qword [rcx + 0x330] ; arg1
│           0x180064ee1      488bd9         mov rbx, rcx               ; arg1
│           0x180064ee4      488b4808       mov rcx, qword [rax + 8]
│           0x180064ee8      4883792000     cmp qword [rcx + 0x20], 0
│       ┌─< 0x180064eed      0f84e2020000   je 0x1800651d5
│       │   0x180064ef3      48833900       cmp qword [rcx], 0
│      ┌──< 0x180064ef7      0f84d8020000   je 0x1800651d5
│      ││   0x180064efd      488d4b18       lea rcx, [rbx + 0x18]
│      ││   0x180064f01      41b801000000   mov r8d, 1
│      ││   0x180064f07      e81448fdff     call 0x180039720
│      ││   0x180064f0c      488d8b2001..   lea rcx, [rbx + 0x120]
│      ││   0x180064f13      41b802000000   mov r8d, 2
│      ││   0x180064f19      e80248fdff     call 0x180039720
│      ││   0x180064f1e      488d8b2802..   lea rcx, [rbx + 0x228]
│      ││   0x180064f25      41b80f000000   mov r8d, 0xf               ; 15
│      ││   0x180064f2b      e8f047fdff     call 0x180039720
│      ││   0x180064f30      488b833003..   mov rax, qword [rbx + 0x330]
│      ││   0x180064f37      488b4808       mov rcx, qword [rax + 8]
│      ││   0x180064f3b      488b4120       mov rax, qword [rcx + 0x20]
│      ││   0x180064f3f      80781300       cmp byte [rax + 0x13], 0
│     ┌───< 0x180064f43      7432           je 0x180064f77
│     │││   0x180064f45      ff1565610200   call qword [sym.imp.KERNEL32.dll_GetConsoleWindow] ; [0x18008b0b0:8]=0xa6fc8 re
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000120 ........!..L.!This program cannot be r

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: present — claim only: DYNAMIC_BASE set but no .reloc section — loads at preferred base
  64-bit high-entropy ASLR: present — 64-bit high-entropy ASLR flag set
  Data Execution Prevention: present — Data Execution Prevention flag set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 5
  heapalloc @ 0x180058ef2 (fcn.180058eb4)
  heapalloc @ 0x18005b1c1 (fcn.18005b16c)
  virtualalloc @ 0x18007036f (fcn.1800702d0)
  virtualalloc @ 0x18007ffc7 (fcn.18007ffa0)
  cryptgenrandom @ 0x18003f8ef (fcn.18003f810)

## revai_tools_audit
  error: revai_tools_audit: timeout


<!-- evidence_assembler: used 21351/60000 chars across 12 tools -->