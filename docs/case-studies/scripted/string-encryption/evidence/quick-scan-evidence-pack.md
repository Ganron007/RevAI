## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=263db990612712d7 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=44, sha256=263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca
  Anomalies (1): XorInLoop (code)
  High-signal anomaly locations: XorInLoop@686
  YARA (info, 1 total): FASM
  Functions (2): sub_4010a8@680, EntryPoint@512
  (low-signal/noise imports: 2 omitted)
  Strings/apis (1 total): ExitProcess
  Strings (other, 7 items, omitted)
  Recovered structures (12): MZ, PE, OptionalHeader, Sections, ImportTable, ImportNames, kernel32.OFT, kernel32.FT, ImportNames, user32.OFT, user32.FT, ImportNames
  Decompilations (2 top functions):
    ### 680 (sub_4010a8, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_4010a8(int32_t param_1)

{
    uint8_t *in_EAX;
    uint8_t unaff_BL;
    uint8_t *puVar1;
    
    puVar1 = in_EAX;
    do {
        *puVar1 = *in_EAX ^ unaff_BL;
        param_1 = param_1 + -1;
        in_EAX = in_EAX + 1;
        puVar1 = puVar1 + 1;
    } while (param_1 != 0);
    return;
}
```
    ### 512 (EntryPoint, score=?)
```c
/* WARNING: Possible PIC construction at 0x0040100f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00401037: Changing call to branch */
/* WARNING: Possible PIC construction at 0x0040105f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00401087: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00401064) */
/* WARNING: Removing unreachable block (ram,0x0040103c) */
/* WARNING: Removing unreachable block (ram,0x00401014) */
/* WARNING: Removing unreachable block (ram,0x0040108c) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    int32_t iVar1;
    uint8_t *puVar2;
    uint8_t *puVar3;
    
    iVar1 = 0x12;
    puVar2 = 0x403000;
    puVar3 = 0x403000;
    do {
        *puVar3 = *puVar2 ^ 0x90;
        iVar1 = iVar1 + -1;
        puVar2 = puVar2 + 1;
        puVar3 = puVar3 + 1;
    } while (iVar1 != 0);
    return;
}
```

## capa evidence (2 total, showing top 2)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  All rules (1): terminate process

## pe_imports (2 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (4)
  Rules: domain, IsPE32, IsWindowsGUI, FASM

## FLOSS strings (6 total)
  apis (1): ExitProcess
  (other strings, 5 items omitted)

<!-- evidence_assembler: used 2516/28000 chars across 5 tools -->