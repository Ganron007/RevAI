## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=c7e2c9b730007847 | packaging=v6.1 -->

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

<!-- evidence_assembler: used 4494/28000 chars across 5 tools -->