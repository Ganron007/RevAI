## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=a2923d838f2d301a | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=6.56, sha256=a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395
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

<!-- evidence_assembler: used 12636/28000 chars across 7 tools -->