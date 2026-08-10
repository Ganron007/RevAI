## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=3476906b2c724a60 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=224, sha256=3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
  Anomalies (15): BigBufferNoXrefMediumToHighEntropy×2 (entropy), CrossSectionJump (code), DllNoRelocation (sections), DuplicatedSectionName×4 (sections), HighEntropy (entropy), HugeFunctionGapAtSectionBoundary×2 (code), HugeGapBetweenFunctions×83 (code), InvalidSizeOfCode (sections), ManyHighValueImmediates×4 (code), PurelyVirtualExecutableSection (sections), SectionMostlyVirtual (sections), SectionNameUnknown×7 (sections), SectionWX (sections), UnbalancedVirtualPhysicalRatio (sections), UnreferencedImports×3 (imports)
  High-signal anomaly locations: ManyHighValueImmediates@51727,1286388,1518970
  YARA (info, 1 total): MSVC_2022_linker
  Functions (15): sub_105f197a@1518970, sub_104fdc27@520231, sub_106410b2@1844402, sub_1050d604@584196, sub_1000d60f@51727, sub_106bc784@2349956, sub_105b8cf4@1286388, sub_10617c8e@1675406, sub_1057665c@1014364, sub_10538a66@761446, sub_10016f71@90993, sub_1073d878@2878584, sub_104e67d2@424914, sub_10626734@1735476, sub_1000c596@47510
  Mid-signal imports: advapi32.OpenProcessToken, kernel32.GetModuleHandleA
  (low-signal/noise imports: 1 omitted)
  Strings/apis (3 total): InitializeSecurity, OpenProcessToken, GetModuleHandleA
  Strings (other, 297 items, omitted)
  Recovered structures (16): MZ, RichHeader, PE, OptionalHeader, Sections, ExportDirectory, ExportNames, OrdinalNameTable, ExportNames, ExportAddressTable, ExportNameTable, ImportNames, ImportTable, kernel32.FT, user32.FT
  Decompilations (3 top functions):
    ### 1518970 (sub_105f197a, score=?)
```c
sub_105f197a {
    // Error while decompiling : not a valid va
}
```
    ### 520231 (sub_104fdc27, score=?)
```c
/* WARNING: Control flow encountered bad instruction data */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_104fdc27(void)

{
    char cVar1;
    undefined4 *puVar2;
    undefined4 *unaff_EBP;
    undefined4 uStack_8;
    
    puVar2 = &stack0xfffffffc;
    cVar1 = '\b';
    do {
        unaff_EBP = unaff_EBP + -1;
        puVar2 = puVar2 + -1;
        *puVar2 = *unaff_EBP;
        cVar1 = cVar1 + -1;
    } while ('\0' < cVar1);
    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
}
```
    ### 1844402 (sub_106410b2, score=?)
```c
sub_106410b2 {
    // Error while decompiling : not a valid va
}
```

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Software Packing'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Software Packing', 'id': 'T1027.002'} (1): packed with Themida
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (1): forwarded export
  All rules (1): decompress data using aPLib

## pe_imports (3 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (10)
  Rules: domain, IP, contains_base64, CRC32_poly_Constant, IsPE32, IsDLL, IsWindowsGUI, IsPacked, HasRichSignature, win_token

## FLOSS strings (5014 total)
  (other strings, 80 items omitted)

<!-- evidence_assembler: used 3214/28000 chars across 5 tools -->