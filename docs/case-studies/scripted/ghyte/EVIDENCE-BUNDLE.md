# Technical Evidence Pack

**sha256:** a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567  
**sample_path:** /opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: upatre/zbot
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Local tools (capa, MalCat) indicate behavioral intent through encryption and defense evasion techniques, while VirusTotal confirms high detection rates as a known trojan/downloader. Obfuscation signals are present but are complemented by malicious behavioral evidence.
- **summary**: The PE file exhibits multiple behavioral signals including encryption (RC4 PRGA) and window hiding from capa, code anomalies like XOR loops and function gaps from MalCat, and YARA rule matches for potential malware families. VirusTotal corroborates with high detection rates for trojan.upatre/zbot, indicating malicious intent beyond mere obfuscation.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | capa top_rules | `encrypt data using RC4 PRGA` | Behavioral intent for obfuscation under Defense Evasion (T1027), a common malware technique to hide payloads or communic |
| capa | capa top_rules | `hide graphical window` | Defense evasion tactic (T1564.003) to conceal malicious activity from users or analysis tools. |
| malcat | views/anomalies | `XorInLoop` | Code anomaly indicating XOR-based encryption or unpacking operations, often used in malware for obfuscation or payload e |
| malcat | views/anomalies | `HugeGapBetweenFunctions` | Anomaly suggesting hidden data or code between functions, typical in packed malware to store encrypted payloads. |
| yara | yara matches | `Safeguard_103_Simonzh` | YARA rule match that may indicate specific malware family or packer signature, contributing to malicious indicators. |
| external_ti | VirusTotal detection | `malicious=68` | High detection rate by 68/71 engines, with tags like 'spreader' and 'self-delete', confirming known malicious behavior a |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Packed/protected PE executable using ZProtect/Safeguard protection with RC4 encryption and hidden-window capabilities. The binary is heavily obfuscated with only 6 functions recoverable from a 26KB sample, garbled strings throughout, and many unresolved indirect calls. CAPA confirms RC4 PRGA encryption (T1027), hidden window creation (T1564.003), and command-line argument processing. The combination of commercial-grade packing, cryptographic obfuscation, and stealth window capabilities indicates a malicious payload concealed within the protector wrapper. Persistence mechanisms were not observed in the analysis. C2 network communications were not identified. Defense impairment techniques were not detected.

### deep key_evidence
- `"YARA: ZProtect_v144_lifeengines and Safeguard_103_Simonzh packer signatures matched"`
- `"CAPA: 'encrypt data using RC4 PRGA' - RC4 encryption for obfuscation (T1027)"`
- `"CAPA: 'hide graphical window' - Defense Evasion via Hidden Window (T1564.003)"`
- `"CAPA: 'accept command line arguments' - Execution via Command and Scripting Interpreter (T1059)"`
- `"Ghidra: Only 6 functions identified in 26KB binary indicating heavy packing"`
- `"Ghidra: High cyclomatic complexity in FUN_00401686 (CC=14, 17 blocks) and FUN_00402bdb (CC=15, 35 blocks)"`
- `"Ghidra: 11 of 12 call targets in FUN_00401686 resolve to sub_0 (unresolved indirect calls typical of packed code)"`
- `"IDA: 96 strings found but most are garbled random bytes (e.g., '00N,t', 'qH1Hl', 'VXlt|NO') indicating encrypted/compressed data"`
- `"Ghidra: All 24 imports are GUI-only (USER32, GDI32, KERNEL32) despite hidden-window capability suggesting real payload loaded dynamically"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567
size: 26624
type: PE
architecture: X86
entrypoint_ea: 2688
entropy: 6.04
file_name: ghyte.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| header | 0 | 1024 | 0 | - |
| .text | 1024 | 10752 | 12288 | RX |
| .data | 13312 | 3584 | 4096 | RW |
| .rsrc | 17408 | 11264 | 12288 | R |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2005_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2008_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |

### Anomalies (4)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| NoValidCertificate | 4 | integrity | 1 | Certificate data directory does not point to a valid certificate (maybe corrupted ?) |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| HugeGapBetweenFunctions | 2 | code | 1 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### Anomaly Locations (high-signal)
- **NoChecksum**
  - `328`: 
- **XorInLoop**
  - `8221`: 

### High-Signal Strings (1 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 16742 | `kernel32.dll` |

### Top Strings (170 extracted; showing 80)
| EA | String |
|---|---|
| 17712 | `<assembly xmlns=..fo>
</assembly>` |
| 14284 | `DestroyWindow` |
| 14259 | `dip quip` |
| 16742 | `kernel32.dll` |
| 14272 | `edit` |
| 16768 | `gdi32.dll` |
| 14304 | `button` |
| 14239 | `summer` |
| 16676 | `user32.dll` |
| 14234 | `lunt` |
| 28252 | `"""DB""` |
| 28260 | `"""BB""` |
| 77 | `!This program ca..in DOS mode.
$` |
| 16550 | `TranslateMessage` |
| 28199 | `""""` |
| 28188 | `"""""""` |
| 28292 | `"""""""` |
| 28244 | `"""#"""` |
| 16584 | `DispatchMessageA` |
| 16630 | `PostQuitMessage` |
| 16708 | `GetModuleHandleA` |
| 28268 | `""$BD""` |
| 16464 | `SendMessageA` |
| 16616 | `GetMessageA` |
| 16728 | `GetLastError` |
| 16690 | `GetCommandLineA` |
| 16498 | `RegisterClassExA` |
| 13849 | `6Ltt` |
| 16382 | `KillTimer` |
| 8750 | `@@%@` |
| 9931 | `@@m` |
| 10163 | `@@%@` |
| 14150 | `;NNt` |
| 13874 | `Tqq1` |
| 28276 | `""$"$""` |
| 16570 | `BeginPaint` |
| 16438 | `LoadCursorA` |
| 16410 | `GetWindowRect` |
| 28284 | `""$"$""` |
| 16648 | `ShowWindow` |
| 9288 | `@%%@@` |
| 8818 | `pun@@` |
| 8810 | `0wwl?` |
| 9253 | `@%%@@` |
| 8580 | `@%%@@` |
| 488 | `.text` |
| 568 | `.rsrc` |
| 1157 | `qH1Hl` |
| 14277 | `static` |
| 527 | ``.data` |
| 14246 | `momenr` |
| 14227 | `terras` |
| 16370 | `SetTimer` |
| 16758 | `TextOutA` |
| 3387 | ``X+ww76m@@` |
| 16662 | `UpdateWindow` |
| 16604 | `EndPaint` |
| 16536 | `LoadBitmapA` |
| 16518 | `CreateWindowExA` |
| 16480 | `DefWindowProcA` |
| 16452 | `LoadIconA` |
| 16426 | `FillRect` |
| 16394 | `SetWindowPos` |
| 13830 | `;XZkq` |
| 10178 | `%@%%@` |
| 14253 | `Arial` |
| 8999 | `98Hl6` |
| 8845 | `KQjO:N` |
| 14298 | `loret` |
| 207 | `7Richu` |
| 1109 | `00N,t` |
| 7954 | `O8T=y` |
| 3300 | `8V}x8` |
| 4548 | `Y["fh` |
| 7762 | `)wPwm` |
| 7735 | `H]wyvK`` |
| 6133 | `@hZK` |
| 9220 | `%%@@` |
| 10046 | `]Ek` |
| 7934 | `qw4m` |

### Imports (24)
| EA | Name | Type | Refs |
|---|---|---|---|
| 13312 | gdi32.TextOutA | IMPORT | 17 |
| 13320 | kernel32.GetModuleHandleA | IMPORT | 3 |
| 13324 | kernel32.GetCommandLineA | IMPORT | 1 |
| 13328 | kernel32.GetLastError | IMPORT | 4 |
| 13336 | user32.LoadIconA | IMPORT | 2 |
| 13340 | user32.SendMessageA | IMPORT | 14 |
| 13344 | user32.DefWindowProcA | IMPORT | 1 |
| 13348 | user32.RegisterClassExA | IMPORT | 1 |
| 13352 | user32.CreateWindowExA | IMPORT | 4 |
| 13356 | user32.LoadBitmapA | IMPORT | 1 |
| 13360 | user32.TranslateMessage | IMPORT | 1 |
| 13364 | user32.LoadCursorA | IMPORT | 1 |
| 13368 | user32.DispatchMessageA | IMPORT | 1 |
| 13372 | user32.EndPaint | IMPORT | 1 |
| 13376 | user32.GetMessageA | IMPORT | 1 |
| 13380 | user32.PostQuitMessage | IMPORT | 1 |
| 13384 | user32.ShowWindow | IMPORT | 1 |
| 13388 | user32.UpdateWindow | IMPORT | 1 |
| 13392 | user32.FillRect | IMPORT | 1 |
| 13396 | user32.GetWindowRect | IMPORT | 1 |
| 13400 | user32.KillTimer | IMPORT | 2 |
| 13404 | user32.SetWindowPos | IMPORT | 1 |
| 13408 | user32.BeginPaint | IMPORT | 1 |
| 13412 | user32.SetTimer | IMPORT | 1 |

### Functions (8)
| EA | Name |
|---|---|
| 8155 | sub_402bdb |
| 9297 | sub_403051 |
| 2694 | sub_401686 |
| 2688 | EntryPoint |
| 3003 | sub_4017bb |
| 1432 | sub_401198 |
| 8895 | sub_402ebf |
| 7686 | sub_402a06 |

### Decompilations (top 6)
#### 8155 — sub_402bdb
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_402bdb(void)

{
    uint8_t uVar1;
    uint8_t uVar2;
    uint32_t uVar3;
    int32_t iVar4;
    uint32_t uVar5;
    int32_t *piVar6;
    int32_t *piVar7;
    int32_t *piVar8;
    int32_t *piVar9;
    uint8_t *puVar10;
    uint8_t *puVar11;
    
    piVar8 = 0x4044cc + 1;
    puVar10 = piVar8 + *0x4044cc;
    piVar6 = puVar10 + -1;
    iVar4 = ([0x0x4044c8] - *0x4044cc) + -4;
    piVar7 = piVar8;
    004044c8 = iVar4;
    piRam004044cc = puVar10;
    do {
        *puVar10 = *puVar10 ^ [0x0x4041fc] + *piVar7;
        piVar9 = piVar8;
        if (piVar7 != piVar6) {
            piVar9 = piVar7 + 1;
        }
        puVar10 = puVar10 + 1;
        iVar4 = iVar4 + -1;
        piVar7 = piVar9;
    } while (iVar4 != 0);
    (*user32.SendMessageA)([0x0x404468], 0x111, 0x4044c8, 0x39);
    iVar4 = [0x0x4044c8];
    puVar10 = 0x4044bc;
    puVar11 = 0x4044cc;
    do {
        *puVar11 = *puVar10;
        puVar10 = puVar10 + 1;
        puVar11 = puVar11 + 1;
        iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    0040444c = [0x0x4041f3] + 0x4041f7;
    piVar7 = 0x4041f7 + 1;
    piVar6 = piVar7 + *0x4041f7;
    puVar10 = piVar7 + *0x4041f7;
    uVar5 = 0;
    uVar3 = *piVar7 + 1;
    puVar11 = 0x4044bc;
    piRam00404448 = piVar6;
    while( true ) {
        if (piVar6 <= piVar7) {
            for (iVar4 = [0x0x40444c] - puVar10; iVar4 != 0; iVar4 = iVar4 + -1) {
                *puVar11 = *puVar10;
                puVar10 = puVar10 + 1;
                puVar11 = puVar11 + 1;
            }
            return;
        }
        if (uVar3 < uVar5) break;
        for (iVar4 = uVar3 - uVar5; iVar4 != 0; iVar4 = iVar4 + -1) {
            *puVar11 = *puVar10;
            puVar10 = puVar10 + 1;
            puVar11 = puVar11 + 1;
        }
        uVar1 = *(piVar7 + 1);
        uVar2 = *(piVar7 + 2);
        uVar5 = uVar2;
        for (uVar3 = uVar5; uVar3 != 0; uVar3 = uVar3 - 1) {
            *puVar11 = uVar1;
            puVar11 = puVar11 + 1;
        }
        piVar8 = piVar7 + 3;
        uVar1 = *piVar8;
        if (uVar2 == 0xff) {
            if (uVar1 == 0xff) {
                uVar3 = *(piVar7 + 1);
                piVar7 = piVar7 + 6;
            }
            else {
                uVar3 = 0xff;
                piVar7 = piVar8;
            }
        }
        else if (uVar1 == 0xff) {
            uVar3 = *(piVar7 + 1);
            piVar7 = piVar7 + 6;
        }
        else {
            uVar3 = uVar1;
            piVar7 = piVar8;
        }
    }
    return;
}

```
#### 9297 — sub_403051
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_403051(undefined4 param_1,int32_t param_2,uint32_t *param_3,int32_t param_4)

{
    undefined uVar1;
    code *pcVar2;
    undefined4 uVar3;
    int32_t iVar4;
    uint32_t uVar5;
    uint32_t uVar6;
    int32_t *piVar7;
    undefined *puVar8;
    code *pcVar9;
    undefined *puVar10;
    uint32_t *puVar11;
    code *pcVar12;
    int32_t *piVar13;
    uint32_t uVar14;
    undefined auStack_30 [4];
    undefined auStack_2c [24];
    int32_t iStack_14;
    int32_t iStack_10;
    int32_t iStack_c;
    int32_t iStack_8;
    
    pcVar2 = kernel32.GetModuleHandleA;
    if (param_2 == 0x401) {
        puVar10 = *param_3;
        puVar8 = param_3[1];
        iVar4 = 7;
        do {
            uVar1 = *puVar10;
            puVar10 = puVar10 + 1;
            *puVar8 = uVar1;
            puVar8 = puVar8 + -param_4;
            iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
        return 0;
    }
    if (param_2 == 1) {
        (*user32.LoadBitmapA)([0x0x4041c7], 0x66);
        00404458 = (*kernel32.GetLastError)();
        iVar4 = [0x0x4041c7];
        (*user32.CreateWindowExA)(0, "button", "summer", 0x10010000, 0xc, 10, 0x154, 0x26, param_1, 2, [0x0x4041c7], 0);
        00404440 = (*kernel32.GetLastError)();
        0040445c = 00404440;
        004044d4 = 00404440;
        00404454 = (*user32.CreateWindowExA)(0, "edit", 0, 0x40000000, 5, 0x4a, 500, 0x1ae, param_1, 1, iVar4, 0);
        004041e3 = (*kernel32.GetLastError)();
        (*user32.CreateWindowExA)(0, "button", "summer", 0x40000001, 5, 0x17c, 0xba, 0x22, 1, 2, iVar4, 0);
        004041e3 = (*kernel32.GetLastError)();
        0040445c = 004041e3;
        00404464 = (*user32.SendMessageA)(param_1, 0x111, 0x40419d, 0x31);
        (*user32.SendMessageA)(param_1, 0x111, 00404464, 0x2e);
        return 0;
    }
    if (param_2 == 0x113) {
        00404440 = [0x0x404440] + [0x0x404458];
        (*user32.SendMessageA)(param_1, 0x111, 0, 00404440);
        return 0;
    }
    if (param_2 != 2) {
        if (param_2 == 5) {
            (*user32.GetWindowRect)(param_1, &iStack_14);
            (*user32.SendMessageA)(param_1, 0x111, 0, ((iStack_c - iStack_14) - (iStack_8 - iStack_10)) + 1);
            return 0;
        }
        if (param_2 == 0xf) {
            (*user32.BeginPaint)(param_1, auStack_30);
            (*gdi32.TextOutA)();
            (*user32.EndPaint)(param_1, auStack_2c);
            return 0;
        }
        if (param_2 != 0x111) {
            uVar3 = (*user32.DefWindowProcA)(param_1, param_2, param_3, param_4);
            return uVar3;
        }
        if (param_4 == 0x2e) {
            (*user32.SetTimer)(param_1, 1, 10, 0);
            return 0;
        }
        if (param_4 == 0x31) {
            iVar4 = 5;
            puVar11 = param_3 + 5;
            do {
                uVar14 = *puVar11;
                puVar11 = puVar11 + 1;
                *param_3 = uVar14 + *param_3;
                param_3 = param_3 + 1;
                iVar4 = iVar4 + -1;
            } while (iVar4 != 0);
            return 0;
        }
        if (param_4 == 0x579) {
            [0x0x4041cf] = [0x0x4041cf] + 8;
            004041f3 = (*([0x0x4043bc] + -1 + [0x0x4044d4]))();
            004044c8 = 004041f3;
            sub_402bdb();
            pcVar2 = sub_4017bb(user32.KillTimer, "DestroyWindow");
            (*pcVar2)([0x0x404468]);
            return 0;
        }
        if (param_4 == 0x37) {
            [0x0x404468] = param_1;
            iVar4 = [0x0x4041e3];
            if ([0x0x4041e3] == 0) {
                iVar4 = (*0x4044bc)();
            }
            (*user32.SendMessageA)(param_1, 0x111, 0, iVar4 + 1);
            return 0;
        }
        if (param_4 != 0x36) {
            if (param_4 == 0x39) {
                uVar14 = *param_3;
                pcVar2 = param_3[1];
                pcVar9 = 0x4044bc + uVar14;
                uVar5 = [0x0x4041c5];
                uVar6 = uVar5;
            
```
#### 2694 — sub_401686
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401686(void)

{
    char cVar1;
    
    00404474 = (*kernel32.GetCommandLineA)();
    004041c7 = (*kernel32.GetModuleHandleA)(0);
    [0x0x4043f0] = 0x30;
    [0x0x4043f4] = 2;
    0x4043f8 = sub_403051;
    [0x0x4043fc] = 0;
    [0x0x404400] = 0;
    puRam004041cf = &stack0xfffffffc;
    00404404 = 004041c7;
    0040440c = (*user32.LoadCursorA)(0, 0x7f00);
    00404408 = (*user32.LoadIconA)(0, 0x7f00);
    [0x0x404418] = "lunt";
    [0x0x404410] = 0xf;
    0040441c = 00404408;
    (*user32.RegisterClassExA)(0x4043f0);
    00404468 = (*user32.CreateWindowExA)
                             (0, "lunt", 0x4043e7, 0xcf0000, 0xfffff8f8, 0xfffff862, 0x1fe, 0x1e0, 0, 0, [0x0x4041c7]
                              , 0);
    (*user32.ShowWindow)(00404468, 5);
    (*user32.UpdateWindow)([0x0x404468]);
    while( true ) {
        cVar1 = (*user32.GetMessageA)(0x404420, 0, 0, 0);
        if (cVar1 == '\0') break;
        (*user32.TranslateMessage)(0x404420);
        (*user32.DispatchMessageA)(0x404420);
    }
    sub_402a06();
    return;
}

```

### Carved Files (2)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 10036 |
| ? | DIB | 216 |

### Virtual Files (4)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| BMP/101/en-us | 174 | - |
| ICO/1/en-us | 10036 | - |
| GRPICO/100/en-us | 20 | - |
| MANIF/1/en-us | 346 | - |

### Structures (30)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 240 |
| OptionalHeader | 264 |
| Sections | 488 |
| gdi32.FT | 13312 |
| kernel32.FT | 13320 |
| user32.FT | 13336 |
| ImportTable | 16180 |
| gdi32.OFT | 16260 |
| kernel32.OFT | 16268 |
| user32.OFT | 16284 |
| ImportNames | 16368 |
| Resources | 17408 |
| Resources.BMP | 17456 |
| Resources.ICO | 17480 |
| Resources.GRPICO | 17504 |
| Resources.MANIF | 17528 |
| Resources.BMP.101 | 17552 |
| Resources.ICO.1 | 17576 |
| Resources.GRPICO.100 | 17600 |
| Resources.MANIF.1 | 17624 |
| Resources.BMP.101.en-us | 17648 |
| Resources.ICO.1.en-us | 17664 |
| Resources.GRPICO.100.en-us | 17680 |
| Resources.MANIF.1.en-us | 17696 |
| Manifest | 17712 |
| Resources.ICO.1.en-us.Data | 18064 |
| Resources.GRPICO.100.en-us.Data | 28104 |
| Resources.BMP.101.en-us.Data | 28128 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 3 · duration_s: 1.02

| Rule | ATT&CK | MBC |
|---|---|---|
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| hide graphical window | T1564.003:Hide Artifacts |  |

## PE Imports / Signals
import_count: 24

## YARA Matches (pipeline)
Total matches: 7

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| contains_base64 | - | $a@12748 len=12 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasRichSignature | - | $a0@208 len=4 |
| Safeguard_103_Simonzh | - | $a@2688 len=5 |
| ZProtect_v144_lifeengines | - | $a@2688 len=23 |

## Generated YARA Meta
```json
{
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 12748,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 208,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Safeguard_103_Simonzh",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2688,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "ZProtect_v144_lifeengines",
      "path": "/opt/samples/corpus/malware/a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567/ghyte.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2688,
          "length": 23,
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
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Spywaller.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_OmniRat.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_OmniRat.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Wshell_ChineseSpam.yar: error[E014]: invalid regular expression\n  --> /opt/samples/rules/flat/Wshell_ChineseSpam.yar:17:42\n   |\n17 |         $c = /if ?\\(\\$_POST\\[Submit\\]\\) ?{/\n   |                                   
```

## FLOSS Strings
Total strings: 72 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 72}`

### High-signal FLOSS
- `kernel32.dll`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `7Richu`
- ``.data`
- `VXlt|NO`
- `%h@~qU`
- `}|)8Or6`
- ``X+ww76m@@`
- `auf je`
- `%h@pfQ`
- `H]wyvK``
- `y8u(@%`
- `mf tTl`
- `%%:}[t`
- `|`|s\$:~`
- `KQjO:N`
- `%@%?vp`
- `t7{p|Xz`
- `2uPj1hp@@`
- `GGGGBBBBIu`
- `SwW&:~8Ol`
- `8n+|Bj`
- `terras`
- `summer`
- `momenr`
- `dip quip`
- `static`
- `DestroyWindow`
- `button`
- `SetTimer`
- `KillTimer`
- `SetWindowPos`
- `GetWindowRect`
- `FillRect`
- `LoadCursorA`
- `LoadIconA`
- `SendMessageA`
- `DefWindowProcA`
- `RegisterClassExA`
- `CreateWindowExA`
- `LoadBitmapA`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401680
```asm
┌ 6: entry0 ();
│           0x00401680      e801000000     call fcn.00401686
└           0x00401685      c3             ret
```
### 0x00401686
```asm
; CALL XREF from entry0 @ 0x401680(x)
┌ 299: fcn.00401686 ();
│           0x00401686      55             push ebp
│           0x00401687      8bec           mov ebp, esp
│           0x00401689      ff150c404000   call dword [sym.imp.kernel32.dll_GetCommandLineA] ; 0x40400c ; "0M" ; LPSTR GetCommandLineA(void)
│           0x0040168f      a374444000     mov dword [0x404474], eax   ; [0x404474:4]=0
│           0x00401694      6a00           push 0
│           0x00401696      ff1508404000   call dword [sym.imp.kernel32.dll_GetModuleHandleA] ; 0x404008 ; "BM" ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)
│           0x0040169c      892dcf414000   mov dword [0x4041cf], ebp   ; [0x4041cf:4]=97 ; "a"
│           0x004016a2      a304444000     mov dword [0x404404], eax   ; [0x404404:4]=0
│           0x004016a7      a3c7414000     mov dword [0x4041c7], eax   ; [0x4041c7:4]=17
│           0x004016ac      c705f04340..   mov dword [0x4043f0], 0x30  ; '0'
│                                                                      ; [0x4043f0:4]=0
│           0x004016b6      c705f44340..   mov dword [0x4043f4], 2     ; [0x4043f4:4]=0
│       ┌─< 0x004016c0      eb04           jmp 0x4016c6
..
│       │   ; CODE XREF from fcn.00401686 @ 0x4016c0(x)
│       └─> 0x004016c6      c705f84340..   mov dword [0x4043f8], 0x403051 ; 'Q0@'
│                                                                      ; [0x4043f8:4]=0
│           0x004016d0      c705fc4340..   mov dword [0x4043fc], 0     ; [0x4043fc:4]=0
│           0x004016da      c705004440..   mov dword [0x404400], 0     ; [0x404400:4]=0
│           0x004016e4      68007f0000     push 0x7f00
│           0x004016e9      6a00           push 0
│           0x004016eb      ff1534404000   call dword [sym.imp.user32.dll_LoadCursorA] ; 0x404034 ; "4L" ; HCURSOR LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName)
│           0x004016f1      a30c444000     mov dword [0x40440c], eax   ; [0x40440c:4]=0
│           0x004016f6      68007f0000     push 0x7f00
│           0x004016fb      6a00           push 0
│           0x004016fd      ff1518404000   call dword [sym.imp.user32.dll_LoadIconA] ; 0x404018 ; "BL" ; HICON LoadIconA(HINSTANCE hInstance, LPCSTR lpIconName)
│           0x00401703      a308444000     mov dword [0x404408], eax   ; [0x404408:4]=0
│           0x00401708      a31c444000     mov dword [0x40441c], eax   ; [0x40441c:4]=0
│           0x0040170d      c705184440..   mov dword [0x404418], 0x40439a ; [0x404418:4]=0
│           0x00401717      c705104440..   mov dword [0x404410], 0xf   ; [0x404410:4]=0
│           0x00401721      68f0434000     push 0x4043f0
│           0x00401726      ff1524404000   call dword [sym.imp.user32.dll_RegisterClassExA] ; 0x404024 ; "pL" ; ATOM RegisterClassExA(const WNDCLASSEXA *ARG_0)
│           0x0040172c      6a00           push 0
│           0x0040172e      ff35c7414000   push dword [0x4041c7]
│           0x00401734      6a00           push 0
│           0x00401736      6a00        
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r

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
  - `user32.dll!LoadIconA`
  - `user32.dll!SendMessageA`
  - `user32.dll!DefWindowProcA`
  - `user32.dll!RegisterClassExA`
  - `user32.dll!CreateWindowExA`
  - `kernel32.dll!GetModuleHandleA`
  - `kernel32.dll!GetCommandLineA`
  - `kernel32.dll!GetLastError`
  - `gdi32.dll!TextOutA`
