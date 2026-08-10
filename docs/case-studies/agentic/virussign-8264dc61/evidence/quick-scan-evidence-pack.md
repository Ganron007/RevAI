## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=bf95bc98c0a4fc25 | packaging=v6.1 -->

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

<!-- evidence_assembler: used 3889/28000 chars across 5 tools -->