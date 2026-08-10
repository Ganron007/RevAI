## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=cbddf52b9cc0cf6f | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=84, sha256=cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4
  Anomalies (4): BssNonEmpty (entropy), FewStrings (strings), InvalidBaseOfData (sections), SectionWX (sections)
  YARA (info, 1 total): FASM
  Functions (3): sub_40102b@1067, EntryPoint@1024, sub_401132@1330
  Mid-signal imports: user32.SendMessageA, kernel32.GetModuleHandleA
  (low-signal/noise imports: 6 omitted)
  Strings/apis (11 total): OriginalFilename, FileDescription, StringFileInfo, FileVersion, VarFileInfo, GetModuleHandleA, GetDlgItemTextA, SetDlgItemTextA, SendMessageA, ExitProcess, LoadIconA
  Strings (other, 25 items, omitted)
  Carved files (1): DIB@13892 (135208 bytes)
  Virtual files (4): ICO/1/unk, DLG/37/en-us, GRPICO/17/unk, VER/1/unk
  Recovered structures (29): MZ, PE, OptionalHeader, Sections, ImportTable, ImportNames, kernel32.OFT, kernel32.FT, ImportNames, user32.OFT, user32.FT, ImportNames, Resources, Resources.DLG, Resources.DLG.37
  Decompilations (3 top functions):
    ### 1067 (sub_40102b, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_40102b(undefined4 param_1,int32_t param_2,int32_t param_3)

{
    undefined4 uVar1;
    uint32_t uVar2;
    int32_t extraout_EDX;
    int32_t iVar3;
    int32_t iVar4;
    uint8_t *puVar5;
    
    if (param_2 == 0x110) {
        uVar1 = (*user32.LoadIconA)([0x0x402188], 0x11);
        (*user32.SendMessageA)(param_1, 0x80, 1, uVar1);
        return 1;
    }
    if (param_2 == 0x111) {
        if (param_3 != 2) {
            if (param_3 != 1) {
                return 1;
            }
            uVar2 = (*user32.GetDlgItemTextA)(param_1, 100, 0x402004, 0x40);
            if ((4 < uVar2) && (uVar2 < 10)) {
                iVar3 = 0;
                puVar5 = 0x402004;
                do {
                    iVar3 = iVar3 + *puVar5;
                    uVar2 = uVar2 - 1;
                    puVar5 = puVar5 + 1;
                } while (uVar2 != 0);
                sub_401132();
                iVar3 = (*user32.GetDlgItemTextA)(param_1, 0x65, 0x402044, 0x40, iVar3);
                if (9 < iVar3) {
                    iVar4 = 0;
                    puVar5 = 0x402044;
                    do {
                        iVar4 = iVar4 + *puVar5;
                        iVar3 = iVar3 + -1;
                        puVar5 = puVar5 + 1;
                    } while (iVar3 != 0);
                    sub_401132();
                    if (iVar4 == extraout_EDX) {
                        (*user32.SetDlgItemTextA)(param_1, 0x65, "good!", 0x100);
                        return 1;
                    }
                }
            }
            goto code_r0x00401111;
        }
    }
    else if (param_2 != 0x10) {
        return 0;
    }
    (*user32.EndDialog)(param_1, 0);
code_r0x00401111:
    (*user32.SetDlgItemTextA)(param_1, 0x65, "bad!", 0x100);
    return 1;
}
```
    ### 1024 (EntryPoint, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 EntryPoint(void)

{
    undefined4 uVar1;
    uint32_t uVar2;
    int32_t extraout_EDX;
    uint8_t *puVar3;
    undefined4 uVar4;
    int32_t iVar5;
    int32_t iVar6;
    
    00402188 = (*kernel32.GetModuleHandleA)(0);
    iVar6 = 0;
    iVar5 = 0x25;
    uVar4 = 00402188;
    (*user32.DialogBoxParamA)(00402188, 0x25, 0, sub_40102b, 0);
    (*kernel32.ExitProcess)(0);
    if (iVar5 == 0x110) {
        uVar1 = (*user32.LoadIconA)([0x0x402188], 0x11);
        (*user32.SendMessageA)(uVar4, 0x80, 1, uVar1);
        return 1;
    }
    if (iVar5 == 0x111) {
        if (iVar6 != 2) {
            if (iVar6 != 1) {
                return 1;
            }
            uVar2 = (*user32.GetDlgItemTextA)(uVar4, 100, 0x402004, 0x40);
            if ((4 < uVar2) && (uVar2 < 10)) {
                iVar5 = 0;
                puVar3 = 0x402004;
                do {
                    iVar5 = iVar5 + *puVar3;
                    uVar2 = uVar2 - 1;
                    puVar3 = puVar3 + 1;
                } while (uVar2 != 0);
                sub_401132();
                iVar5 = (*user32.GetDlgItemTextA)(uVar4, 0x65, 0x402044, 0x40, iVar5);
                if (9 < iVar5) {
                    iVar6 = 0;
                    puVar3 = 0x402044;
                    do {
                        iVar6 = iVar6 + *puVar3;
                        iVar5 = iVar5 + -1;
                        puVar3 = puVar3 + 1;
                    } while (iVar5 != 0);
                    sub_401132();
                    if (iVar6 == extraout_EDX) {
                        (*user32.SetDlgItemTextA)(uVar4, 0x65, "good!", 0x100);
                        return 1;
                    }
                }
            }
            goto code_r0x00401111;
        }
    }
    else if (iVar5 != 0x10) {
        return 0;
    }
    (*user32.EndDialog)(uVar4, 0);
code_r0x00401111:
    (*user32.SetDlgItemTextA)(uVar4, 0x65, "bad!", 0x100);
    return 1;
```
    ### 1330 (sub_401132, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401132(void)

{
    int32_t iVar1;
    
    iVar1 = 0x31337;
    do {
        iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    return;
}
```

## capa evidence (1 total, showing top 1)
  All rules (1): terminate process

## pe_imports (8 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (10)
  Rules: domain, IP, contains_base64, IsPE32, IsWindowsGUI, FASM, FASM_15x, FASM_v13x_additional, FASM_v15x, FASM_v13x

## FLOSS strings (30 total)
  apis (11): GetModuleHandleA, ExitProcess, GetDlgItemTextA, SetDlgItemTextA, LoadIconA, SendMessageA, StringFileInfo, FileDescription, FileVersion, OriginalFilename, VarFileInfo
  (other strings, 19 items omitted)

<!-- evidence_assembler: used 5760/28000 chars across 5 tools -->