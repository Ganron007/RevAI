## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=ba3558c89e9ff2e3 | packaging=v6.1 -->

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
  - Constants/registry (3): registry::HKEY_CURRENT_USER×3, registry::HKEY_USERS×2, registry::HKEY_LOCAL_MACHINE×2
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

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 2 functions (asm)
  ### 0x1400084b8
```c
┌ 242: entry0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_8h @ rbp-0x8
│           0x1400084b8      e848feffff     call fcn.140008305
│           0x1400084bd      c8200000       enter 0x20, 0              ; 32
│           0x1400084c1      4c897c24f8     mov qword [rsp - 8], r15
│           0x1400084c6      4883ec08       sub rsp, 8
│           0x1400084ca      4989e7         mov r15, rsp
│           0x1400084cd      4883ec20       sub rsp, 0x20
│           0x1400084d1      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x1400084d5      4831f6         xor rsi, rsi
│           0x1400084d8      4801c6         add rsi, rax
│           0x1400084db      4883c03c       add rax, 0x3c              ; 60
│           0x1400084df      4831d2         xor rdx, rdx
│           0x1400084e2      8b10           mov edx, dword [rax]
│           0x1400084e4      4883ec08       sub rsp, 8
│           0x1400084e8      48893424       mov qword [rsp], rsi
│           0x1400084ec      488b0424       mov rax, qword [rsp]
│           0x1400084f0      4883c408       add rsp, 8
│           0x1400084f4      4801d0         add rax, rdx
│           0x1400084f7      480588000000   add rax, 0x88              ; 136
│           0x1400084fd      4883ec08       sub rsp, 8
│           0x140008501      48890424       mov qword [rsp], rax
│           0x140008505      488b0c24       mov rcx, qword [rsp]
│           0x140008509      4883c408       add rsp, 8
│           0x14000850d      48c7c00000..   mov rax, 0
│           0x140008514      8b01           mov eax, dword [rcx]
│           0x140008516      4801f0         add rax, rsi
│           0x140008519      50             push rax
│           0x14000851a      488b0c24       mov rcx, qword [rsp]
│           0x14000851e      4883c408       add rsp, 8
│           0x140008522      56             push rsi
│           0x140008523      488b1424       mov rdx, qword [rsp]
│           0x140008527      4883c408       add rsp, 8
│           0x14000852b      488d05acf3..   lea rax, [0x1400078de]
│           0x140008532      4883ec08       sub rsp, 8
│           0x140008536      48890c24       mov qword [rsp], rcx
│           0x14000853a      48c7c1619a..   mov rcx, 0xfffffffffffe9a61
│           0x140008541      4883ec08       sub rsp, 8
│           0x140008545      48890c24       mov qword [rsp], rcx
│           0x140008549      48c7c1cb73..   mov rcx, 0x173cb
│       ┌─> 0x140008550      48ffc0         inc rax
```
  ### 0x140008305
```c
; CALL XREF from entry0 @ 0x1400084b8(x)
┌ 446: fcn.140008305 (int64_t arg2);
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_1h @ rbp-0x1
│           ; var int64_t var_2h @ rbp-0x2
│           ; var int64_t var_3h @ rbp-0x3
│           ; var int64_t var_4h @ rbp-0x4
│           ; var int64_t var_5h @ rbp-0x5
│           ; var int64_t var_6h @ rbp-0x6
│           ; var int64_t var_7h @ rbp-0x7
│           ; var int64_t var_bp_8h @ rbp-0x8
│           ; var int64_t var_9h @ rbp-0x9
│           ; var int64_t var_ah @ rbp-0xa
│           ; var int64_t var_bh @ rbp-0xb
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_7fh @ rbp-0x7f
│           ; var int64_t var_8h @ rsp+0x218
│           0x140008305      488b442408     mov rax, qword [var_8h]
│           0x14000830a      4883e200       and rdx, 0                 ; arg2
│      ┌┌─> 0x14000830e      48ffc8         dec rax
│      ╎╎   0x140008311      6681384d5a     cmp word [rax], 0x5a4d     ; 'MZ'
│     ┌───< 0x140008316      750b           jne 0x140008323
│    ┌────< 0x140008318      7414           je 0x14000832e
│    ││╎╎   0x14000831a      e85e000000     call 0x14000837d
│    ││╎╎   0x14000831f      b3c7           mov bl, 0xc7               ; 199
│    ││╎╎   0x140008321      9f             lahf
│    ││╎╎   0x140008322      5e             pop rsi
│    │└└──< 0x140008323      75e9           jne 0x14000830e
│    │  ╎   0x140008325      e8fcffffff     call 0x140008326
│    │  ╎   0x14000832a      8bcf           mov ecx, edi
│    │  ╎   0x14000832c  ~   350b8b503c     xor eax, 0x3c508b0b
│    └────> 0x14000832e      8b503c         mov edx, dword [rax + 0x3c]
│       ╎   0x140008331      81fa00040000   cmp edx, 0x400             ; 1024
│       └─< 0x140008337      73d5           jae 0x14000830e
│           0x140008339      482db5480000   sub rax, 0x48b5
│           0x14000833f      4801c2         add rdx, rax
│           0x140008342      4881c2b548..   add rdx, 0x48b5
│           0x140008349      4805b5480000   add rax, 0x48b5
│           0x14000834f      66813a5045     cmp word [rdx], 0x4550     ; 'PE'
│       ┌─< 0x140008354      7506           jne 0x14000835c
│      ┌──< 0x140008356      7442           je 0x14000839a
│      ││   0x140008358      82             invalid
..
│      │└─> 0x14000835c      744d           je 0x1400083ab
│      │    0x14000835e      75ae           jne 0x14000830e
│      │    0x140008360      488d05cdfe
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 13918/60000 chars across 9 tools -->