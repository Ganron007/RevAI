# Technical Evidence Pack

**sha256:** cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4  
**sample_path:** /opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe  
**project_name:** Hexorcist 3 - Weeks 20-30

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 20
- **family_guess**: Hexorcist keygen
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra reports fewer strings (26) and functions (2) compared to IDA (1 string, 3 functions) and Malcat (36 strings, 3 functions), indicating potential data source gaps. The Ghidra imports table is empty, but IDA lists 8 imports, and Malcat confirms consistent imports. Decompilation is sourced from Malcat as per evidence.
- **summary**: This sample is a keygen template for 'Hexorcist' based on strings and decompiled code. It performs serial validation in a dialog GUI but shows no malicious behavioral intent (e.g., file destruction, C2, persistence, credential theft). All signals align with benign software protection testing or keygen use, with neutral anomalies like section entropy.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| floss | floss strings | `HEXORCIST KEYGEN TEMPLATE` | String indicates the sample is a keygen template, not malware, with no behavioral intent for harm. |
| malcat | decompilations | `DialogFunc (sub_40102b)` | Decompiled code shows serial validation logic with outputs 'good!' and 'bad!', typical of benign crackmes, lacking malic |
| malcat | strings | `SERIAL:` | String used for serial input in the GUI, supporting keygen behavior without indicators of credential theft or C2. |
| capa | capa rules | `terminate process` | Only behavioral rule found is benign process termination, confirming no malicious intent such as data destruction or per |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is a benign CTF crackme challenge from the Hexorcist series, compiled with FASM. It implements a simple Windows dialog-based password checker using DialogBoxParamA/GetDlgItemTextA, with a 'good!' success string. Only 8 GUI-related imports (zero suspicious signals), 2-3 functions total, and no malicious capabilities (no network, persistence, injection, or crypto). Capa matched only 'terminate process' (ExitProcess). YARA matched only FASM compiler artifacts. The filename 'angr_crackme2.exe' explicitly identifies it as a crackme for symbolic execution practice.

### deep key_evidence
- `"Filename 'angr_crackme2.exe' explicitly labeled as crackme"`
- `"Copyright strings: 'SAS HEXORCIST', 'HEXORCIST ASM TEMPLATE' (CTF challenge series)"`
- `"Only 8 benign GUI imports: DialogBoxParamA, GetDlgItemTextA, SetDlgItemTextA, LoadIconA, SendMessageA, EndDialog, GetModuleHandleA, ExitProcess"`
- `"pe_import_signals: 0 suspicious signals from 8 imports"`
- `"capa: 1 rule match \u2014 'terminate process' (C0018) only \u2014 benign"`
- `"IDA identified 'DialogFunc' at 0x40113B with string_ref to 'good!' (classic crackme success message)"`
- `"Only 2 functions in binary: entry (306 bytes) and FUN_00401132 (13 bytes) \u2014 minimal code surface"`
- `"YARA: no malicious family rules matched, only FASM compiler artifacts"`
- `"No network, persistence, injection, crypto, or file manipulation APIs present"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4
size: 139264
type: PE
architecture: X86
entrypoint_ea: 1024
entropy: 84
file_name: angr_crackme2.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 33 | - |
| .text | 1024 | 512 | 4096 | 86 | RWX |
| .idata | 5120 | 512 | 4096 | 0 | RW |
| .data | 9216 | 512 | 4096 | 0 | RW |
| .rsrc | 13312 | 136704 | 139264 | 85 | R |
| .bss | 152576 | 0 | 4096 | 0 | RW |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| FASM | compiler | INFO | 70 | detects fasm using DOS stub |

### Anomalies (4)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidBaseOfData | 4 | sections | 1 | at least one data section starts before BaseOfData, or BaseOfData is not the start of a data section |
| BssNonEmpty | 3 | entropy | 1 | Bss Region/section is not empty |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| FewStrings | 2 | strings | 0 | file does not have many identified strings (less than 1% of the file is composed of strings) |

### High-Signal Strings (1 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 5180 | `KERNEL32.DLL` |

### Top Strings (36 extracted; showing 36)
| EA | String |
|---|---|
| 5180 | `KERNEL32.DLL` |
| 5194 | `USER32.DLL` |
| 9216 | `good!` |
| 9222 | `bad!` |
| 149600 | `hexo1.EXE` |
| 149158 | `VS_VERSION_INFO` |
| 149566 | `OriginalFilename` |
| 149344 | `HEXORCIST ASM TEMPLATE` |
| 149286 | `040904E4` |
| 13590 | `HEXORCIST KEYGEN TEMPLATE` |
| 149428 | `Copyright SAS HEXORCIST` |
| 149310 | `FileDescription` |
| 149522 | `ProductVersion` |
| 149250 | `StringFileInfo` |
| 149658 | `Translation` |
| 149482 | `FileVersion` |
| 77 | `!This program ca.. in DOS mode.
$` |
| 13644 | `MS Sans Serif` |
| 149398 | `LegalCopyright` |
| 149626 | `VarFileInfo` |
| 5234 | `GetModuleHandleA` |
| 5344 | `GetDlgItemTextA` |
| 5362 | `SetDlgItemTextA` |
| 5392 | `SendMessageA` |
| 5326 | `DialogBoxParamA` |
| 13730 | `SERIAL:` |
| 416 | `.bss` |
| 13694 | `NAME:` |
| 536 | `.rsrc` |
| 496 | `.data` |
| 376 | `.text` |
| 456 | `.idata` |
| 5254 | `ExitProcess` |
| 5380 | `LoadIconA` |
| 13858 | `C&ancel` |
| 5408 | `EndDialog` |

### Imports (8)
| EA | Name | Type | Refs |
|---|---|---|---|
| 5220 | kernel32.GetModuleHandleA | IMPORT | 2 |
| 5224 | kernel32.ExitProcess | IMPORT | 1 |
| 5296 | user32.DialogBoxParamA | IMPORT | 2 |
| 5300 | user32.GetDlgItemTextA | IMPORT | 2 |
| 5304 | user32.SetDlgItemTextA | IMPORT | 2 |
| 5308 | user32.LoadIconA | IMPORT | 1 |
| 5312 | user32.SendMessageA | IMPORT | 1 |
| 5316 | user32.EndDialog | IMPORT | 1 |

### Functions (3)
| EA | Name |
|---|---|
| 1067 | sub_40102b |
| 1024 | EntryPoint |
| 1330 | sub_401132 |

### Decompilations (top 6)
#### 1067 — sub_40102b
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
#### 1024 — EntryPoint
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
}

```
#### 1330 — sub_401132
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

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 135208 |

### Virtual Files (4)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/unk | 135208 | - |
| DLG/37/en-us | 308 | - |
| GRPICO/17/unk | 20 | - |
| VER/1/unk | 536 | - |

### Structures (29)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| ImportTable | 5120 |
| ImportNames | 5180 |
| kernel32.OFT | 5208 |
| kernel32.FT | 5220 |
| ImportNames | 5232 |
| user32.OFT | 5268 |
| user32.FT | 5296 |
| ImportNames | 5324 |
| Resources | 13312 |
| Resources.DLG | 13360 |
| Resources.DLG.37 | 13384 |
| Resources.GRPICO | 13408 |
| Resources.GRPICO.17 | 13432 |
| Resources.ICO | 13456 |
| Resources.ICO.1 | 13480 |
| Resources.VER | 13504 |
| Resources.VER.1 | 13528 |
| Resources.DLG.37.en-us | 13552 |
| Resources.DLG.37.en-us.Data | 13568 |
| Resources.ICO.1.unk | 13876 |
| Resources.ICO.1.unk.Data | 13892 |
| Resources.GRPICO.17.unk | 149100 |
| Resources.GRPICO.17.unk.Data | 149116 |
| Resources.VER.1.unk | 149136 |
| VersionInfo | 149152 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.81

| Rule | ATT&CK | MBC |
|---|---|---|
| terminate process |  | C0018:Terminate Process |

## PE Imports / Signals
import_count: 8

## YARA Matches (pipeline)
Total matches: 10

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@4024 len=2 |
| contains_base64 | - | $a@1650 len=16 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| FASM | - |  |
| FASM_15x | - | $a@1024 len=13 |
| FASM_v13x_additional | - | $a@1024 len=9 |
| FASM_v15x | - | $b@1024 len=13 |
| FASM_v13x | - | $b@1024 len=9 |

## Generated YARA Meta
```json
{
  "rule_count": 10,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 4024,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1650,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": []
    },
    {
      "rule": "FASM",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": []
    },
    {
      "rule": "FASM_15x",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1024,
          "length": 13,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "FASM_v13x_additional",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1024,
          "length": 9,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "FASM_v15x",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": [
        {
          "id": "$b",
          "offset": 1024,
          "length": 13,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "FASM_v13x",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe",
      "strings": [
        {
          "id": "$b",
          "offset": 1024,
          "length": 9,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^
```

## FLOSS Strings
Total strings: 30 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 30}`

### High-signal FLOSS
- `KERNEL32.DLL`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `.idata`
- `Sj@hD @`
- `KERNEL32.DLL`
- `USER32.DLL`
- `GetModuleHandleA`
- `ExitProcess`
- `DialogBoxParamA`
- `GetDlgItemTextA`
- `SetDlgItemTextA`
- `LoadIconA`
- `SendMessageA`
- `EndDialog`
- `HEXORCIST KEYGEN TEMPLATE`
- `MS Sans Serif`
- `SERIAL:`
- `C&ancel`
- `VS_VERSION_INFO`
- `StringFileInfo`
- `040904E4`
- `FileDescription`
- `HEXORCIST ASM TEMPLATE`
- `LegalCopyright`
- `Copyright SAS HEXORCIST`
- `FileVersion`
- `ProductVersion`
- `OriginalFilename`
- `hexo1.EXE`
- `VarFileInfo`
- `Translation`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401000
```asm
;-- section..text:
┌ 43: entry0 ();
│           0x00401000      6a00           push 0                      ; [00] -rwx section size 4096 named .text
│           0x00401002      ff1564304000   call dword [sym.imp.KERNEL32.DLL_GetModuleHandleA] ; 0x403064 ; "p0" ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)
│           0x00401008      a388214000     mov dword [0x402188], eax   ; [0x402188:4]=0
│           0x0040100d      6a00           push 0
│           0x0040100f      682b104000     push 0x40102b               ; '+\x10@'
│           0x00401014      6a00           push 0
│           0x00401016      6a25           push 0x25                   ; '%' ; 37
│           0x00401018      50             push eax
│           0x00401019      ff15b0304000   call dword [sym.imp.USER32.DLL_DialogBoxParamA] ; 0x4030b0 ; INT_PTR DialogBoxParamA(HINSTANCE hInstance, LPCSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam)
│           0x0040101f      09c0           or eax, eax
│       ┌─< 0x00401021      7400           je 0x401023
│       └─> 0x00401023      6a00           push 0
└           0x00401025      ff1568304000   call dword [sym.imp.KERNEL32.DLL_ExitProcess] ; 0x403068 ; VOID ExitProcess(UINT uExitCode)
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
- hook_candidates:
  - `KERNEL32.DLL!GetModuleHandleA`
  - `KERNEL32.DLL!ExitProcess`
  - `USER32.DLL!DialogBoxParamA`
  - `USER32.DLL!GetDlgItemTextA`
  - `USER32.DLL!SetDlgItemTextA`
  - `USER32.DLL!LoadIconA`
  - `USER32.DLL!SendMessageA`
