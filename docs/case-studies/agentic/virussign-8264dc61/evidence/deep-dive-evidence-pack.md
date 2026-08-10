## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=bf95bc98c0a4fc25 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=18, sha256=bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
  Anomalies (11): BigBufferNoXrefMediumToHighEntropy×2 (entropy), CodeSectionNotExecutable (sections), EmbeddedProgram (embedding), InvalidSizeOfInitializedData (sections), NoChecksum (integrity), SectionGap (sections), SectionNameUnknown×2 (sections), SectionWX×2 (sections), SizeOfRawDataNotAligned×3 (sections), UnreferencedImports×113 (imports), XorInLoop×2 (code)
  High-signal anomaly locations: NoChecksum@216; XorInLoop@54824,54896
  YARA (info, 2 total): HideInternetActivity, FingerprintEnvironment
  Functions (15): EntryPoint@54786, sub_431c04@61956, sub_431c11@61969, sub_431c1e@61982, sub_431c2b@61995, sub_431c38@62008, sub_431c45@62021, sub_431c52@62034, sub_431c5f@62047, sub_431c6c@62060, sub_431c79@62073, sub_431c86@62086, sub_431c93@62099, sub_431ca0@62112, sub_431cad@62125
  Top high-signal imports (score≥8, 6 of 113):
    [10] user32.CreateDesktopA
    [10] user32.DestroyWindow
    [10] user32.GetThreadDesktop
    [10] user32.SetThreadDesktop
    [9] advapi32.RegCreateKeyExA
    [9] advapi32.RegSetValueExA
  Mid-signal imports: kernel32.CreateProcessA, kernel32.CreateThread, kernel32.TerminateProcess, user32.SendMessageA, kernel32.DeleteFileA, kernel32.GetProcAddress, kernel32.LoadLibraryA, advapi32.RegOpenKeyExA, advapi32.RegQueryValueExA, kernel32.CreateFileA, kernel32.GetModuleHandleA
  (low-signal/noise imports: 96 omitted)
  Strings/apis (192 total): DeleteUrlCacheEntry, GetComputerNameA, GetUserNameA, GetVersion, GetVersionExA, GetEnvironmentStringsA, CoCreateInstance, LocalAlloc, GetCurrentThreadId, DeleteFileA, GetCurrentProcessId, GetForegroundWindow, GetSystemDirectoryA, CreateThread, FindFirstUrlCacheEntryA
  Strings (other, 108 items, omitted)
  Carved files (1): PE@123392 (56320 bytes)
  Recovered structures (24): MZ, PE, OptionalHeader, Sections, ImportTable, ole32.OFT, oleaut32.OFT, wininet.OFT, kernel32.OFT, user32.OFT, gdi32.OFT, advapi32.OFT, crtdll.OFT, msvcrt.OFT, ole32.FT
  Decompilations (3 top functions):
    ### 54786 (EntryPoint, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    uint32_t *puVar1;
    
    puVar1 = 0x401000;
    do {
        *puVar1 = *puVar1 ^ 0x462530e4;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x408ecc);
    puVar1 = 0x42b000;
    do {
        *puVar1 = *puVar1 ^ 0xb6d16c5;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x42e1d0);
    in(0x58);
    do {
    /* WARNING: Do nothing block with infinite loop */
    } while( true );
}
```
    ### 61956 (sub_431c04, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_431c04(void)

{
    /* WARNING: Could not recover jumptable at 0x00431c0f. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*ole32.CoCreateInstance)();
    return;
}
```
    ### 61969 (sub_431c11, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_431c11(void)

{
    /* WARNING: Could not recover jumptable at 0x00431c1c. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*ole32.CLSIDFromString)();
    return;
}
```

## capa evidence (1 total, showing top 1)
  All rules (1): contain an embedded PE file

## pe_imports (113 imports, 4 high-signal)
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (15)
  Rules: domain, IP, contains_base64, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message, AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER, SEH_Save, SEH_Init, win_mutex, win_registry, win_files_operation, Str_Win32_Wininet_Library

## FLOSS strings (715 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 5 functions (asm)
  ### 0x00430005
```c
┌ 139: fcn.00430005 ();
│       ╎   0x00430005      60             pushal
│       ╎   0x00430006      90             nop
│       ╎   0x00430007      b800104000     mov eax, section..text      ; 0x401000
│       ╎   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc
│       ╎   0x00430011      90             nop
│       ╎   0x00430012      b9e4302546     mov ecx, 0x462530e4
│       ╎   0x00430017      90             nop
│       ╎   0x00430018      90             nop
│       ╎   0x00430019      90             nop
│       ╎   0x0043001a      85c0           test eax, eax
│       ╎   0x0043001c      90             nop
│       ╎   0x0043001d      90             nop
│       ╎   0x0043001e      90             nop
│       ╎   0x0043001f      90             nop
│       ╎   0x00430020      90             nop
│       ╎   0x00430021      90             nop
│      ┌──< 0x00430022      742a           je 0x43004e
│     ┌───> 0x00430024      90             nop
│     ╎│╎   0x00430025      90             nop
│     ╎│╎   0x00430026      90             nop
│     ╎│╎   0x00430027      90             nop
│     ╎│╎   0x00430028      3108           xor dword [eax], ecx
│     ╎│╎   0x0043002a      90             nop
│     ╎│╎   0x0043002b      90             nop
│     ╎│╎   0x0043002c      90             nop
│     ╎│╎   0x0043002d      90             nop
│     ╎│╎   0x0043002e      90             nop
│     ╎│╎   0x0043002f      40             inc eax
│     ╎│╎   0x00430030      40             inc eax
│     ╎│╎   0x00430031      90             nop
│     ╎│╎   0x00430032      90             nop
│     ╎│╎   0x00430033      90             nop
│     ╎│╎   0x00430034      90             nop
│     ╎│╎   0x00430035      90             nop
│     ╎│╎   0x00430036      90             nop
│     ╎│╎   0x00430037      90             nop
│     ╎│╎   0x00430038      90             nop
│     ╎│╎   0x00430039      90             nop
│     ╎│╎   0x0043003a      40             inc eax
│     ╎│╎   0x0043003b      90             nop
│     ╎│╎   0x0043003c      40             inc eax
│     ╎│╎   0x0043003d      90             nop
│     ╎│╎   0x0043003e      90             nop
│     ╎│╎   0x0043003f      90             nop
│     ╎│╎   0x00430040      90             nop
│     ╎│╎   0x00430041      90             nop
│     ╎│╎   0x00430042      90             nop
│     ╎│╎   0x00430043      90             nop
│     ╎│╎   0x00430044      90             nop
│     ╎│╎   0x00430045      39d8           cmp eax, eb
```
  ### 0x004312b0
```c
┌ 133: sym.imp.ole32.DLL_CoCreateInstance ();
│           0x004312b0      98             cwde
│           0x004312b1      1403           adc al, 3
│           0x004312b3  ~   00ac140300..   add byte [esp + edx + 0x14be0003], ch ; [0x14be0003:1]=255
│           ;-- CLSIDFromString:
..
│           0x004312ba      0300           add eax, dword [eax]
│           ;-- CoUninitialize:
│           0x004312bc      ce             into
│           0x004312bd      1403           adc al, 3
│           0x004312bf      0000           add byte [eax], al
│           0x004312c1      0000           add byte [eax], al
│           0x004312c3  ~   00e0           add al, ah
│           ;-- SysAllocString:
..
│           0x004312c5      1403           adc al, 3
│           0x004312c7      0000           add byte [eax], al
│           0x004312c9      0000           add byte [eax], al
│           0x004312cb  ~   00f2           add dl, dh
│           ;-- DeleteUrlCacheEntry:
..
│           0x004312cd      1403           adc al, 3
│           0x004312cf  ~   0008           add byte [eax], cl
│           ;-- FindFirstUrlCacheEntryA:
..
│           0x004312d1  ~   1503002215     adc eax, 0x15220003
│           ;-- FindNextUrlCacheEntryA:
..
│           0x004312d6      0300           add eax, dword [eax]
│           0x004312d8      0000           add byte [eax], al
│           0x004312da      0000           add byte [eax], al
│           ;-- ExitProcess:
│           0x004312dc      3c15           cmp al, 0x15                ; 21
│           0x004312de      0300           add eax, dword [eax]
│           ;-- ExpandEnvironmentStringsA:
│           0x004312e0      4a             dec edx
│           0x004312e1  ~   1503006615     adc eax, 0x15660003
│           ;-- GetCommandLineA:
..
│           0x004312e6      0300           add eax, dword [eax]
│           ;-- GetComputerNameA:
│       ┌─< 0x004312e8      7815           js 0x4312ff
│       │   0x004312ea      0300           add eax, dword [eax]
│       │   ;-- GetCurrentProcessId:
│       │   0x004312ec  ~   8c150300a215   mov word [0x15a20003], ss   ; [0x15a20003:2]=0xffff pe_overlay
│       │   ;-- GetCurrentThreadId:
..
│       │   0x004312f2      0300           add eax, dword [eax]
│       │   ;-- GetExitCodeThread:
│       │   0x004312f4  ~   b8150300cc     mov eax, 0xcc000315
│       │   ;-- GetFileSize:
..
│       │   0x004312f9  ~   150300da15     adc eax, 0x15da0003
│       │   ;-- GetModuleFileNameA:
..
│       │   0x004312fe  
```
  ### 0x00431334
```c
┌ 11: sym.imp.KERNEL32.DLL_IsBadWritePtr ();
│           0x00431334      da16           ficom dword [esi]
│           0x00431336      0300           add eax, dword [eax]
│           ;-- LoadLibraryA:
└       ┌─< 0x00431338  ~   ea160300fa..   ljmp 0x316
│       │   ;-- LocalAlloc:
..
```
  ### 0x00431340
```c
┌ 68: sym.imp.KERNEL32.DLL_LocalFree ();
│           0x00431340      0817           or byte [edi], dl
│           0x00431342      0300           add eax, dword [eax]
│           ;-- OpenMutexA:
│           0x00431344      1417           adc al, 0x17
│           0x00431346      0300           add eax, dword [eax]
│           ;-- CreateFileA:
│           0x00431348      2217           and dl, byte [edi]
│           0x0043134a      0300           add eax, dword [eax]
│           ;-- ReadFile:
│           0x0043134c      3017           xor byte [edi], dl
│           0x0043134e      0300           add eax, dword [eax]
│           ;-- RtlUnwind:
│           0x00431350      3c17           cmp al, 0x17                ; 23
│           0x00431352      0300           add eax, dword [eax]
│           ;-- SetFilePointer:
│           0x00431354      48             dec eax
│           0x00431355      17             pop ss
│           0x00431356      0300           add eax, dword [eax]
│           ;-- CreateMutexA:
│           0x00431358      5a             pop edx
│           0x00431359      17             pop ss
│           0x0043135a      0300           add eax, dword [eax]
│           ;-- Sleep:
│           0x0043135c      6a17           push 0x17                   ; 23
│           0x0043135e      0300           add eax, dword [eax]
│           ;-- TerminateProcess:
│      ┌──< 0x00431360      7217           jb 0x431379
│      │    0x00431362      0300           add eax, dword [eax]
│      │    ;-- VirtualQuery:
│      │    0x00431364      8617           xchg byte [edi], dl
│      │    0x00431366      0300           add eax, dword [eax]
│      │    ;-- CreateProcessA:
│      │    0x00431368      96             xchg esi, eax
│      │    0x00431369      17             pop ss
│      │    0x0043136a      0300           add eax, dword [eax]
│      │    ;-- WaitForSingleObject:
│      │    0x0043136c      a817           test al, 0x17               ; 23
│      │    0x0043136e      0300           add eax, dword [eax]
│      │    ;-- WideCharToMultiByte:
│      │    0x00431370  ~   be170300d4     mov esi, 0xd4000317
│      │    ;-- WinExec:
..
│      │    0x00431375      17             pop ss
│      │    0x00431376      0300           add eax, dword [eax]
│      │    ;-- WriteFile:
│      │    0x00431378  ~   de17           ficom word [edi]
│      └──> 0x00431379      17             pop ss
│           0x0043137a      0300           add eax, dword [eax]
│           ;-- lstrlenA
```
  ### 0x00431384
```c
┌ 2611: sym.imp.KERNEL32.DLL_CreateThread (int32_t arg_1h, int32_t arg_41h, int32_t arg_4eh, int32_t arg_50h, int32_t arg_53h, int32_t arg_65h, int32_t arg_66h, int32_t arg_6ch, int32_t arg_6fh, int32_t arg_72h, int32_t arg_73h);
│           ; arg int32_t arg_1h @ ebp+0x1
│           ; arg int32_t arg_41h @ ebp+0x41
│           ; arg int32_t arg_4eh @ ebp+0x4e
│           ; arg int32_t arg_50h @ ebp+0x50
│           ; arg int32_t arg_53h @ ebp+0x53
│           ; arg int32_t arg_65h @ ebp+0x65
│           ; arg int32_t arg_66h @ ebp+0x66
│           ; arg int32_t arg_6ch @ ebp+0x6c
│           ; arg int32_t arg_6fh @ ebp+0x6f
│           ; arg int32_t arg_72h @ ebp+0x72
│           ; arg int32_t arg_73h @ ebp+0x73
│           0x00431384      0218           add bl, byte [eax]
│           0x00431386      0300           add eax, dword [eax]
│           ;-- DeleteFileA:
│           0x00431388      1218           adc bl, byte [eax]
│           0x0043138a      0300           add eax, dword [eax]
│           0x0043138c      0000           add byte [eax], al
│           0x0043138e      0000           add byte [eax], al
│           ;-- GetWindowTextA:
│           0x00431390      2018           and byte [eax], bl
│           0x00431392      0300           add eax, dword [eax]
│           ;-- GetWindowRect:
│           0x00431394      3218           xor bl, byte [eax]
│           0x00431396      0300           add eax, dword [eax]
│           ;-- FindWindowA:
│           0x00431398      42             inc edx
│           0x00431399      1803           sbb byte [ebx], al
│           0x0043139b  ~   005018         add byte [eax + 0x18], dl
│           ;-- GetWindow:
..
│           0x0043139e      0300           add eax, dword [eax]
│           ;-- GetClassNameA:
│           0x004313a0      5c             pop esp
│           0x004313a1      1803           sbb byte [ebx], al
│           0x004313a3  ~   006c1803       add byte [eax + ebx + 3], ch
│           ;-- SetFocus:
..
│           0x004313a7  ~   007818         add byte [eax + 0x18], bh
│           ;-- GetForegroundWindow:
..
│           0x004313aa      0300           add eax, dword [eax]
│           ;-- LoadCursorA:
│           0x004313ac      8e18           mov ds, word [eax]
│           0x004313ae      0300           add eax, dword [eax]
│           ;-- LoadIconA:
│           0x004313b0      9c             pushfd
│           0x004313b1      1803           sbb byte [ebx], al
│           0x004313b3  ~   00a8180300b4
```

## UPX
  (not packed)


## xorsearch (2 candidates)
  Found XOR 00 position 00000000: 00000080 ......................................
  Found XOR 00 position 0001B800: 00000080 ......................................

<!-- evidence_assembler: used 14608/60000 chars across 9 tools -->