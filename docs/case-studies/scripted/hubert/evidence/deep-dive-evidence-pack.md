## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=0598e95ea5f28e3e | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=223, sha256=0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc
  Anomalies (9): BigBufferNoXrefMediumToHighEntropy×9 (entropy), DllNoRelocation (sections), ExecutableSectionNoCode (sections), HighEntropy (entropy), HugeFunctionGapAtSectionBoundary (code), SectionNameUnknown×2 (sections), SectionWX (sections), UnreferencedImports×79 (imports), XorInLoop×3 (code)
  High-signal anomaly locations: XorInLoop@7008,7021,7187
  YARA (info, 4 total): MSVC_2005_linker, DownloadUsingWininet, ProcessInjectionTargets, ElevatePrivileges
  Functions (7): sub_10002749@6985, sub_100027e5@7141, EntryPoint@6943, _Run@0@7280, sub_100027d7@7127, sub_100027cd@7117, sub_100027d4@7124
  Top high-signal imports (score≥8, 9 of 79):
    [9] wininet.InternetReadFile
    [9] advapi32.RegCreateKeyA
    [9] advapi32.RegSetValueExA
    [9] wininet.InternetCloseHandle
    [9] wininet.InternetOpenA
    [9] wininet.InternetOpenUrlA
    [8] advapi32.AdjustTokenPrivileges
    [8] advapi32.LookupPrivilegeValueW
    [8] kernel32.VirtualAlloc
  Mid-signal imports: advapi32.OpenProcessToken, kernel32.CreateProcessW, kernel32.CreateThread, user32.SendMessageW, advapi32.RegOpenKeyA, advapi32.RegQueryValueExA, kernel32.CreateFileA, kernel32.CreateFileW
  (low-signal/noise imports: 62 omitted)
    Constants/guid (2): guid::IShellLinkW, guid::IPersistFile
  Strings/apis (49 total): InternetReadFile, DisableThreadLibraryCalls, InitializeCriticalSection, DeleteCriticalSection, GetFileAttributesA, CoCreateInstance, InternetOpenUrlA, InternetCloseHandle, InternetOpenA, GetCurrentProcess, InitiateSystemShutdownW, GetVolumeInformationA, OpenProcessToken, CreateDialogParamA, CreateThread
  Strings (other, 251 items, omitted)
  Recovered structures (27): MZ, PE, OptionalHeader, Sections, advapi32.FT, kernel32.FT, shell32.FT, shlwapi.FT, user32.FT, wininet.FT, ntdll.FT, ole32.FT, ImportTable, advapi32.OFT, kernel32.OFT
  Decompilations (3 top functions):
    ### 6985 (sub_10002749, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_10002749(undefined4 param_1,char *param_2)

{
    char *extraout_EDX;
    int32_t iVar1;
    bool bVar2;
    undefined4 uVar3;
    
    uVar3 = 0;
    do {
        do {
            bVar2 = *param_2 == 'M';
            func_0x100027b8(uVar3);
            param_2 = extraout_EDX;
        } while (!bVar2);
    } while (extraout_EDX[0x1001] != 'Z');
    sub_100027d7(&stack0xfffffffc);
    iVar1 = 0x10589;
    do {
        iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    sub_100027e5();
    return;
}
```
    ### 7141 (sub_100027e5, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_100027e5(int32_t param_1)

{
    int32_t iVar1;
    int32_t *unaff_ESI;
    int32_t *unaff_EDI;
    
    do {
        iVar1 = 0x11589;
        do {
            iVar1 = iVar1 + -1;
        } while (iVar1 != 0);
        *unaff_EDI = ROUND(ROUND(*unaff_ESI) ^ 0x5d785e);
        unaff_ESI = unaff_EDI + 1;
        param_1 = param_1 + -1;
        unaff_EDI = unaff_ESI;
    } while (param_1 != 0);
    return;
}
```
    ### 6943 (EntryPoint, score=?)
```c
/* WARNING (jumptable): Unable to track spacebase fully for stack */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 EntryPoint(void)

{
    undefined4 uVar1;
    code *UNRECOVERED_JUMPTABLE;
    int32_t unaff_retaddr;
    
    if (unaff_retaddr == 0x75000000) {
        return 0x10000;
    }
    sub_10002749();
    /* WARNING: Could not recover jumptable at 0x100027d2. Too many branches */
    /* WARNING: Treating indirect jump as call */
    uVar1 = (*UNRECOVERED_JUMPTABLE)();
    return uVar1;
}
```

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  ATT&CK {'parts': ['Defense Evasion', 'Virtualization/Sandbox Evasion', 'System Checks'], 'tactic': 'Defense Evasion', 'technique': 'Virtualization/Sandbox Evasion', 'subtechnique': 'System Checks', 'id': 'T1497.001'} (1): reference anti-VM strings targeting Xen
  All rules (1): contain loop

## pe_imports (79 imports, 4 high-signal)
  http_client (InternetOpen) [T1071.001]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (16)
  Rules: domain, IP, contains_base64, Browsers, IsPE32, IsDLL, IsWindowsGUI, IsPacked, Microsoft_Visual_Basic_v50, escalate_priv, win_mutex, win_registry, win_token, win_files_operation, Str_Win32_Wininet_Library, Str_Win32_Internet_API

## FLOSS strings (695 total)
  registry (1): Software\
  apis (16): InternetOpenUrlA, InternetReadFile, InternetOpenA, InternetCloseHandle, GetComputerNameA, CreateMutexW, WaitForSingleObject, GetTickCount, VirtualFree, InitializeCriticalSection, GetVolumeInformationA, GetTempPathW
  (other strings, 63 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 5 functions (asm)
  ### 0x1000271f
```c
┌ 49: entry0 ();
│           0x1000271f      68ffff0000     push 0xffff
│           0x10002724      0fae1424       ldmxcsr dword [esp]
│           0x10002728      58             pop eax
│           0x10002729      6a00           push 0
│           0x1000272b      0fae1c24       stmxcsr dword [esp]
│           0x1000272f      58             pop eax
│           0x10002730      40             inc eax
│           0x10002731      8d905244ff00   lea edx, [eax + 0xff4452]
│           0x10002737      8b1424         mov edx, dword [esp]
│           0x1000273a      4a             dec edx
│           0x1000273b      81faffffff74   cmp edx, 0x74ffffff
│       ┌─< 0x10002741      0f8586000000   jne 0x100027cd
│       │   0x10002747      c9             leave
│       │   0x10002748      c3             ret
        │   ; CALL XREF from entry0 @ 0x100027cd(x)
..
        │   ; CALL XREF from fcn.10002749 @ 0x10002766(x)
│       └─> 0x100027cd      e877ffffff     call fcn.10002749
└           0x100027d2      ffe2           jmp edx
```
  ### 0x10002749
```c
; CALL XREF from entry0 @ 0x100027cd(x)
┌ 111: fcn.10002749 (int32_t arg_10h);
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_10h @ esp+0x20
│           0x10002749      55             push ebp
│           0x1000274a      89e5           mov ebp, esp
│           0x1000274c      83ec04         sub esp, 4
│           0x1000274f      c745fc0000..   mov dword [var_4h], 0
│           0x10002756      660f12442410   movlpd xmm0, qword [arg_10h]
│           0x1000275c      660f7ec2       movd edx, xmm0
│      ┌┌─> 0x10002760      8a02           mov al, byte [edx]
│      ╎╎   0x10002762      34ce           xor al, 0xce                ; 206
│      ╎╎   0x10002764      3c83           cmp al, 0x83                ; 131
│      ╎╎   0x10002766      e84d000000     call fcn.100027b8
│      └──< 0x1000276b      75f3           jne 0x10002760
│       ╎   0x1000276d      8a8201100000   mov al, byte [edx + 0x1001]
│       ╎   0x10002773      34be           xor al, 0xbe                ; 190
│       ╎   0x10002775      3ce4           cmp al, 0xe4                ; 228
│       └─< 0x10002777      75e7           jne 0x10002760
│           0x10002779      81c200202100   add edx, 0x212000
│           0x1000277f      f8             clc
│           0x10002780      81ea00102100   sub edx, 0x211000
│           0x10002786      56             push esi
│           0x10002787      57             push edi
│           0x10002788      53             push ebx
│           0x10002789      55             push ebp
│           0x1000278a      e848000000     call fcn.100027d7
│           0x1000278f      31f6           xor esi, esi
│           0x10002791      ba89050100     mov edx, 0x10589
│       ┌─> 0x10002796      b800160500     mov eax, 0x51600
│       ╎   0x1000279b      89c6           mov esi, eax
│       ╎   0x1000279d      83ea01         sub edx, 1
│       ╎   0x100027a0      85d2           test edx, edx
│       └─< 0x100027a2      75f2           jne 0x10002796
│           0x100027a4      01ee           add esi, ebp
│           0x100027a6      89f7           mov edi, esi
│           0x100027a8      e838000000     call fcn.100027e5
│           0x100027ad      f7db           neg ebx
│           0x100027af      8d149e         lea edx, [esi + ebx*4]
│           0x100027b2      5d             pop ebp
│           0x100027b3      5b             pop ebx
│           0x100027b4      5f             pop edi
│           0x100027b5      5e             pop esi
│           0x100027b6   
```
  ### 0x100027b8
```c
; CALL XREF from fcn.10002749 @ 0x10002766(x)
┌ 21: fcn.100027b8 ();
│           ; var int32_t var_14h @ esp+0x14
│           0x100027b8      60             pushal
│           0x100027b9      89d0           mov eax, edx
│           0x100027bb      8d8000f0ffff   lea eax, [eax - 0x1000]
│           0x100027c1      660f6ec8       movd xmm1, eax
│           0x100027c5      660f7e4c2414   movd dword [var_14h], xmm1
│           0x100027cb      61             popal
└           0x100027cc      c3             ret
```
  ### 0x100027d7
```c
; CALL XREF from fcn.10002749 @ 0x1000278a(x)
┌ 14: fcn.100027d7 ();
│           0x100027d7      89d5           mov ebp, edx
│           0x100027d9      29c0           sub eax, eax
│           0x100027db      8d8c005002..   lea ecx, [eax + eax + 0x250]
│           0x100027e2      89cb           mov ebx, ecx
└           0x100027e4      c3             ret
```
  ### 0x100027e5
```c
; CALL XREF from fcn.10002749 @ 0x100027a8(x)
┌ 73: fcn.100027e5 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           0x100027e5      55             push ebp
│           0x100027e6      89e5           mov ebp, esp
│           0x100027e8      83ec08         sub esp, 8
│           0x100027eb      c745f80000..   mov dword [var_8h], 0
│           0x100027f2      c745fc0000..   mov dword [var_4h], 0
│       ┌─> 0x100027f9      ba89150100     mov edx, 0x11589
│      ┌──> 0x100027fe      0f59d3         mulps xmm2, xmm3
│      ╎╎   0x10002801      9b             wait
│      ╎╎   0x10002802      dbe3           fninit
│      ╎╎   0x10002804      db06           fild dword [esi]
│      ╎╎   0x10002806      db55f8         fist dword [ebp - 8]
│      ╎╎   0x10002809      8b45f8         mov eax, dword [var_8h]
│      ╎╎   0x1000280c      83ea01         sub edx, 1
│      ╎╎   0x1000280f      85d2           test edx, edx
│      └──< 0x10002811      75eb           jne 0x100027fe
│       ╎   0x10002813      355e785d00     xor eax, 0x5d785e
│       ╎   0x10002818      8945f8         mov dword [var_8h], eax
│       ╎   0x1000281b      db45f8         fild dword [ebp - 8]
│       ╎   0x1000281e      db17           fist dword [edi]
│       ╎   0x10002820      b804000000     mov eax, 4
│       ╎   0x10002825      8d3c07         lea edi, [edi + eax]
│       ╎   0x10002828      89fe           mov esi, edi
│       └─< 0x1000282a      e2cd           loop 0x100027f9
│           0x1000282c      c9             leave
└           0x1000282d      c3             ret
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: missing — Data Execution Prevention flag not set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: missing — NO_SEH flag set — no SEH handlers claimed
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 0

## revai_tools_audit (pe, revai_tools_audit)

<!-- evidence_assembler: used 12047/60000 chars across 12 tools -->