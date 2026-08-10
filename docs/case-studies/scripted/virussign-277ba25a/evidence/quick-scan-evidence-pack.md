## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=e891b8f4825a8699 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=201, sha256=e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2
  Anomalies (10): BigBufferNoXrefMediumToHighEntropy×19 (entropy), CodeSectionNotExecutable (sections), DataBetweenHeaderAndFirstSection (headers), GuiSubsystemNoWindowApi (headers), HighEntropy (entropy), ManyHighValueImmediates×8 (code), ManyUniqueImmediateBytes×7 (code), NoChecksum (integrity), RichUnknownTool (rich), SequentialFunction (code)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@276; ManyHighValueImmediates@468021,470101,470896; ManyUniqueImmediateBytes@468021,470101,470896; NoChecksum@272; SequentialFunction@473453
  Functions (15): sub_474643@474179, sub_473970@470896, sub_472e35@468021, sub_47436d@473453, sub_473655@470101, sub_4757ef@478703, sub_475440@477760, sub_474311@473361, sub_4756b8@478392, sub_475768@478568, sub_4735c1@469953, sub_47458b@473995, sub_47598b@479115, sub_4745ee@474094, sub_475722@478498
  Top high-signal imports (score≥8, 1 of 7):
    [10] advapi32.FreeEncryptedFileKeyInfo
  (low-signal/noise imports: 6 omitted)
  Strings/apis (1 total): FreeEncryptedFileKeyInfo
  Strings (other, 299 items, omitted)
  Recovered structures (15): MZ, RichHeader, PE, OptionalHeader, Sections, user32.FT, advapi32.FT, ntdll.FT, kernel32.FT, ImportTable, user32.OFT, advapi32.OFT, ntdll.OFT, kernel32.OFT, ImportNames
  Decompilations (3 top functions):
    ### 474179 (sub_474643, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_474643(code *param_1)

{
    int32_t iVar1;
    code *extraout_ECX;
    code *extraout_ECX_00;
    uint32_t *puVar2;
    code *extraout_ECX_01;
    code *extraout_ECX_02;
    code *extraout_ECX_03;
    code *extraout_ECX_04;
    code *extraout_ECX_05;
    code *extraout_ECX_06;
    code *extraout_ECX_07;
    code *extraout_ECX_08;
    code *extraout_ECX_09;
    code *extraout_ECX_10;
    code *extraout_ECX_11;
    code *extraout_ECX_12;
    code *extraout_ECX_13;
    code *extraout_ECX_14;
    code *extraout_ECX_15;
    code *extraout_ECX_16;
    code *extraout_ECX_17;
    
    (*param_1)();
    func_0x00475882(0xbd9ac2f4);
    (*extraout_ECX_06)();
    func_0x00475882(0xbdabe822);
    (*extraout_ECX_00)();
    func_0x00475882();
    (*extraout_ECX_10)();
    func_0x00475882();
    (*extraout_ECX_07)();
    func_0x00475882();
    (*extraout_ECX_08)(0x401400);
    func_0x00475882(0xbdd57e2a, 0xbdd4f7d6, 0xbdd46f24, 0xbdd3ea02, 0xbdd35f90);
    (*extraout_ECX_09)();
    func_0x00475882(0xbe189b42);
    (*extraout_ECX_14)();
    func_0x00475882(0xbe1b1fe0);
    (*extraout_ECX_04)();
    func_0x00475882(0xbe1f91ee, 0xbe1f1660, 0xbe1e9ddc, 0xbe1e20cc, 0xbe1d9cd4);
    (*extraout_ECX_05)();
    func_0x00475882(0xbe2401e8);
    (*extraout_ECX_13)();
    puVar2 = 0x401400;
    iVar1 = 0;
    do {
        *puVar2 = *puVar2 ^ 0x7c4cea8d;
        *puVar2 = *puVar2 ^ 0x7c4ceb11;
        *puVar2 = *puVar2 ^ 0x7c4ceb99;
        *puVar2 = *puVar2 ^ 0x7c4cec19;
        *puVar2 = *puVar2 ^ 0x7c4cec75;
        *puVar2 = *puVar2 ^ 0x7c4cecd1;
        puVar2 = puVar2 + 1;
        iVar1 = iVar1 + 4;
    } while (iVar1 < 0x71a06);
    (*0x401400)();
    func_0x00475882(0xbebc435a, 0xbebbc540, 0xbebb49d2, 0xbebacb72, 0xbeba4bba);
    (*extraout_ECX_17)();
    func_0x00475882(0xbec24ca4, 0xbec1ce8e, 0xbec13bae, 0xbec0bd24);
    (*extraout_ECX_11)();
    func_0x00475882(0xbec7be66, 0xbec740fa, 0xbec6c576, 0xbec6471
```
    ### 470896 (sub_473970, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_473970(int32_t param_1)

{
    int32_t iVar1;
    unkuint3 Var3;
    uint32_t uVar2;
    uint8_t *puVar4;
    int32_t *piStack00000078;
    uint32_t in_stack_00000094;
    
    iVar1 = *(***(*(param_1 + 0xc) + 0xc) + 0x18);
    piStack00000078 = *(*(iVar1 + *(iVar1 + 0x3c) + 0x78) + iVar1 + 0x20) + iVar1;
    do {
        piStack00000078 = piStack00000078 + 1;
        puVar4 = *piStack00000078 + iVar1;
        uVar2 = 0;
        do {
            Var3 = uVar2 >> 8;
            uVar2 = CONCAT31(Var3, uVar2 ^ *puVar4) << 8 | Var3 >> 0x10;
            puVar4 = puVar4 + 1;
        } while (*puVar4 != 0);
    } while (uVar2 != in_stack_00000094);
    return;
}
```
    ### 468021 (sub_472e35, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_472e35(uint8_t *param_1)

{
    uint32_t in_EAX;
    unkuint3 Var1;
    int32_t *in_stack_0000007c;
    uint32_t in_stack_00000098;
    int32_t in_stack_000000cc;
    
    do {
        if (*param_1 == 0) {
            if (in_EAX == in_stack_00000098) {
                return;
            }
            in_stack_0000007c = in_stack_0000007c + 1;
            param_1 = *in_stack_0000007c + in_stack_000000cc;
            in_EAX = 0;
        }
        Var1 = in_EAX >> 8;
        in_EAX = CONCAT31(Var1, in_EAX ^ *param_1) << 8 | Var1 >> 0x10;
        param_1 = param_1 + 1;
    } while( true );
}
```

## capa evidence (2 total, showing top 2)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encrypt data using RC4 via SystemFunction033
  ATT&CK {'parts': ['Discovery', 'System Location Discovery', 'System Language Discovery'], 'tactic': 'Discovery', 'technique': 'System Location Discovery', 'subtechnique': 'System Language Discovery', 'id': 'T1614.001'} (1): identify system language via API

## pe_imports (7 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (7)
  Rules: domain, IP, contains_base64, IsPE32, IsWindowsGUI, IsPacked, HasRichSignature

## FLOSS strings (1144 total)
  (other strings, 80 items omitted)

<!-- evidence_assembler: used 5769/28000 chars across 5 tools -->