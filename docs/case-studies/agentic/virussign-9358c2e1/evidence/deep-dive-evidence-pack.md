## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=c7e2c9b730007847 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=145, sha256=c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5
  Anomalies (16): BigBufferNoXrefMediumToHighEntropy×41 (entropy), CrossSectionJump (code), EmbeddedProgram×10 (embedding), ExecutableSectionNoCode×2 (sections), HugeFunctionGapAtSectionBoundary (code), InvalidBaseOfCode (sections), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), NoChecksum (integrity), Packed (packers), PurelyVirtualExecutableSection (sections), RelocationsNotInRelocSection (sections), SectionNameUnknown (sections), SectionWX×2 (sections), UnreferencedImports×8 (imports), XorInLoop×2 (code)
  High-signal anomaly locations: NoChecksum@216; XorInLoop@4481815,4482011
  YARA (info, 2 total): UPX, RunShell
  Functions (4): sub_10b4196@4481942, EntryPoint@4481792, sub_10b4158@4481880, sub_10b4327@4482343
  Top high-signal imports (score≥8, 2 of 12):
    [10] crypt32.CertOpenStore
    [8] kernel32.VirtualProtect
  Mid-signal imports: kernel32.LoadLibraryA, kernel32.GetProcAddress
  (low-signal/noise imports: 8 omitted)
  Strings/paths (1 total): ^Q^^gggg^^^^gggg..gggg\\\\gggg\\\\
  Strings/apis (19 total): ShellExecuteW, GetAdaptersAddresses
  Strings (other, 280 items, omitted)
  Carved files (10): PE@4535183 (193536 bytes), PE@4730130 (193536 bytes), PE@7411350 (193536 bytes), PE@7606017 (193536 bytes), PE@7801269 (193536 bytes), PE@7996781 (193536 bytes), PE@8191899 (193536 bytes), PE@8386598 (193536 bytes), PE@8580182 (193536 bytes), PE@8774869 (193536 bytes)
  Recovered structures (21): MZ, PE, OptionalHeader, Sections, UPX.PackHeader, ExceptionTable, TlsDirectory, TLSInitArray, TlsCallbacks, ImportTable, advapi32.FT, crypt32.FT, iphlpapi.FT, kernel32.FT, msvcrt.FT
  Decompilations (3 top functions):
    ### 4481942 (sub_10b4196, score=?)
```c
sub_10b4196 {
    // Error while decompiling : not a valid ea
}
```
    ### 4481792 (EntryPoint, score=?)
```c
/* WARNING: Removing unreachable block (ram,0x010b414a) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    uint8_t *puVar1;
    uint8_t *in_R9;
    
    puVar1 = 0xc6e025;
    do {
        *puVar1 = *puVar1 ^ 0xae;
        puVar1 = puVar1 + 1;
    } while (puVar1 != in_R9);
    [0x0x10aa37c] = 0x712e619e;
    sub_10b4196(0);
    return;
}
```
    ### 4481880 (sub_10b4158, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_10b4158(uint32_t param_1)

{
    undefined4 uVar1;
    uint32_t uVar2;
    undefined4 *puVar3;
    undefined uVar4;
    uint64_t unaff_RBP;
    undefined4 *unaff_RDI;
    
    puVar3 = unaff_RDI + unaff_RBP;
    uVar4 = *puVar3;
    if ((5 < param_1) && (unaff_RBP < 0xfffffffffffffffd)) {
        uVar2 = param_1 - 4;
        do {
            param_1 = uVar2;
            uVar1 = *puVar3;
            puVar3 = puVar3 + 1;
            *unaff_RDI = uVar1;
            unaff_RDI = unaff_RDI + 1;
            uVar2 = param_1 - 4;
        } while (3 < param_1);
        uVar4 = *puVar3;
        if (param_1 == 0) {
            return;
        }
    }
    do {
        puVar3 = puVar3 + 1;
        *unaff_RDI = uVar4;
        param_1 = param_1 - 1;
        uVar4 = *puVar3;
        unaff_RDI = unaff_RDI + 1;
    } while (param_1 != 0);
    return;
}
```

## capa evidence (5 total, showing top 5)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Software Packing'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Software Packing', 'id': 'T1027.002'} (1): packed with UPX
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (1): link function at runtime on Windows
  All rules (2): contain an embedded PE file, terminate process

## pe_imports (12 imports, 3 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]

## YARA matches (12)
  Rules: domain, IP, contains_base64, UPX, android_meterpreter, IsPE64, IsConsole, HasOverlay, suspicious_packer_section, win_mutex, win_files_operation, Str_Win32_Winsock2_Library

## FLOSS strings (10548 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 2 functions (asm)
  ### 0x010b4100
```c
┌ 88: entry0 (int64_t arg4);
│           ; arg int64_t arg4 @ r9
│           0x010b4100      53             push rbx
│           0x010b4101      56             push rsi
│           0x010b4102      57             push rdi
│           0x010b4103      55             push rbp
│           0x010b4104      488d351a9f..   lea rsi, [0x00c6e025]
│           0x010b410b      488dbedb2f..   lea rdi, [rsi - 0x86d025]
│           0x010b4112      50             push rax
│           0x010b4113      53             push rbx
│           0x010b4114      56             push rsi
│           0x010b4115      b3ae           mov bl, 0xae                ; 174
│       ┌─> 0x010b4117      8a06           mov al, byte [rsi]
│       ╎   0x010b4119      30d8           xor al, bl
│       ╎   0x010b411b      8806           mov byte [rsi], al
│       ╎   0x010b411d      48ffc6         inc rsi
│       ╎   0x010b4120      4c39ce         cmp rsi, r9                 ; arg4
│       └─< 0x010b4123      75f2           jne 0x10b4117
│           0x010b4125      5e             pop rsi
│           0x010b4126      5b             pop rbx
│           0x010b4127      58             pop rax
│           0x010b4128      488d877c93..   lea rax, [rdi + 0xca937c]
│           0x010b412f      ff30           push qword [rax]
│           0x010b4131      c7009e612e71   mov dword [rax], 0x712e619e ; [0x712e619e:4]=-1
│           0x010b4137      50             push rax
│           0x010b4138      57             push rdi
│           0x010b4139      31db           xor ebx, ebx
│           0x010b413b      31c9           xor ecx, ecx
│           0x010b413d      4883cdff       or rbp, 0xffffffffffffffff
│           0x010b4141      e850000000     call fcn.010b4196
│           0x010b4146      01db           add ebx, ebx
│       ┌─< 0x010b4148      7402           je 0x10b414c
│       │   0x010b414a      f3c3           repz ret
│       └─> 0x010b414c      8b1e           mov ebx, dword [rsi]
│           0x010b414e      4883eefc       sub rsi, 0xfffffffffffffffc
│           0x010b4152      11db           adc ebx, ebx
│           0x010b4154      8a16           mov dl, byte [rsi]
└           0x010b4156      f3c3           repz ret
```
  ### 0x010b4196
```c
╎   ; CALL XREF from entry0 @ 0x10b4141(x)
┌ 400: fcn.010b4196 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   0x010b4196      fc             cld
│       ╎   0x010b4197      415b           pop r11
│      ┌──< 0x010b4199      eb08           jmp 0x10b41a3
│     ┌───> 0x010b419b      48ffc6         inc rsi
│     ╎│╎   0x010b419e      8817           mov byte [rdi], dl
│     ╎│╎   0x010b41a0      48ffc7         inc rdi
│     ╎│╎   ; CODE XREFS from fcn.010b4196 @ 0x10b4199(x), 0x10b423e(x)
│    ┌─└──> 0x010b41a3      8a16           mov dl, byte [rsi]
│    ╎╎ ╎   0x010b41a5      01db           add ebx, ebx
│    ╎╎┌──< 0x010b41a7      750a           jne 0x10b41b3
│    ╎╎│╎   0x010b41a9      8b1e           mov ebx, dword [rsi]
│    ╎╎│╎   0x010b41ab      4883eefc       sub rsi, 0xfffffffffffffffc
│    ╎╎│╎   0x010b41af      11db           adc ebx, ebx
│    ╎╎│╎   0x010b41b1      8a16           mov dl, byte [rsi]
│    ╎└└──> 0x010b41b3      72e6           jb 0x10b419b
│    ╎  ╎   0x010b41b5      8d4101         lea eax, [rcx + 1]          ; arg1
│    ╎ ┌──< 0x010b41b8      eb07           jmp 0x10b41c1
│    ╎┌───> 0x010b41ba      ffc8           dec eax
│    ╎╎│╎   0x010b41bc      41ffd3         call r11
│    ╎╎│╎   0x010b41bf      11c0           adc eax, eax
│    ╎╎│╎   ; CODE XREF from fcn.010b4196 @ 0x10b41b8(x)
│    ╎╎└──> 0x010b41c1      41ffd3         call r11
│    ╎╎ ╎   0x010b41c4      11c0           adc eax, eax
│    ╎╎ ╎   0x010b41c6      01db           add ebx, ebx
│    ╎╎┌──< 0x010b41c8      750a           jne 0x10b41d4
│    ╎╎│╎   0x010b41ca      8b1e           mov ebx, dword [rsi]
│    ╎╎│╎   0x010b41cc      4883eefc       sub rsi, 0xfffffffffffffffc
│    ╎╎│╎   0x010b41d0      11db           adc ebx, ebx
│    ╎╎│╎   0x010b41d2      8a16           mov dl, byte [rsi]
│    ╎└└──> 0x010b41d4      73e4           jae 0x10b41ba
│    ╎  ╎   0x010b41d6      83e803         sub eax, 3
│    ╎ ┌──< 0x010b41d9      7219           jb 0x10b41f4
│    ╎ │╎   0x010b41db      c1e008         shl eax, 8
│    ╎ │╎   0x010b41de      0fb6d2         movzx edx, dl
│    ╎ │╎   0x010b41e1      09d0           or eax, edx
│    ╎ │╎   0x010b41e3      48ffc6         inc rsi
│    ╎ │╎   0x010b41e6      83f0ff         xor eax, 0xffffffff         ; -1
│    ╎┌───< 0x010b41e9      7458           je 0x10b4243
│    ╎││╎   0x010b41eb      d1f8           sar eax, 1
│    ╎││╎   0x010b41ed      4863e8         movsxd rbp, eax
│   ┌─────
```

## UPX
  (not packed)


## xorsearch (11 candidates)
  Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r
  Found XOR 00 position 00451B8F: 00000080 ........!..L.!This program cannot be r
  Found XOR 00 position 00481512: 00000080 ........!..L.!This program cannot be r
  Found XOR 00 position 0070FE96: 00000080 ........!..L.!This program cannot be r
  Found XOR 00 position 0073F701: 00000080 ........!..L.!This program cannot be r
  Found XOR 00 position 0076F1B5: 00000080 ........!..L.!This program cannot be r
  Found XOR 00 position 0079ED6D: 00000080 ........!..L.!This program cannot be r
  Found XOR 00 position 007CE79B: 00000080 ........!..L.!This program cannot be r
  (and 3 more…)

<!-- evidence_assembler: used 10049/60000 chars across 9 tools -->