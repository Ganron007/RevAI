# Technical Evidence Pack

**sha256:** fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f  
**sample_path:** /opt/samples/corpus/Hexorcist 1 - Weeks 1-8/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe  
**project_name:** Hexorcist 1 - Weeks 1-8

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 30
- **family_guess**: Hexorcist Crackme 7
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra reported an empty imports table due to a known limitation for mixed-mode PEs, but IDA and Malcat consistently identified 9 imports from KERNEL32 and USER32 modules. String counts vary across tools (Ghidra: 28, IDA: 13, FLOSS: 33), reflecting different extraction methodologies. The sample shows obfuscation via XOR encoding and high entropy, but no behavioral evidence of malicious intent such as C2 communication, persistence, or data destruction.
- **summary**: The sample is a PE32 binary identified as a crackme application (Hexorcist Crackme 7). It exhibits obfuscation through XOR encoding and high entropy, but analysis across multiple engines reveals no behavioral indicators of malicious activity such as command-and-control, persistence, credential theft, or data exfiltration. The presence of GUI elements, serial number input, and benign API imports supports its classification as suspicious but not definitively malicious, likely serving as a puzzle or educational tool.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| ida | Imports (IDA) | `rows: (module: KERNEL32, name: GetModuleHandleA), (module: KERNEL32, name: AddVe` | Lists standard Windows API imports for GUI and error handling, indicating a typical benign application with dialog boxes |
| malcat | anomalies | `XorInLoop (code) at address 1034` | Identifies an XOR instruction in a loop at the entry point, which is a common obfuscation technique. However, this is a  |
| floss | strings | `"HEXORCIST CRACKME 7", "SERIAL:", "now this is getting serious"` | These strings strongly suggest the sample is a crackme or keygen challenge, with clear indications of serial number inpu |
| capa | capa | `rule: encode data using XOR (ATT&CK T1027)` | Confirms the use of XOR encoding for obfuscation, aligning with the observed XOR loop. This technique is neutral and doe |
| yara | YARA matches | `rules: domain, IP, contains_base64, IsPE32, IsWindowsGUI, FASM, SEH__vectored` | Multiple YARA matches, but in context, these are likely benign indicators (e.g., PE structure, FASM compiler, SEH for er |
| malcat | static_profile | `entropy: 84, SectionWX anomaly, UnreferencedImports×8` | High entropy and writable-executable section indicate packing or protection, which are neutral signals. Unreferenced imp |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE32 Windows GUI crackme (reverse engineering challenge) from the Hexorcist 1 CTF series. The entry point at 0x401000 is a XOR decryption stub that decrypts 1496 bytes at 0x4012b3 using single-byte key 0x66, then registers the decrypted code as a Vectored Exception Handler via AddVectoredExceptionHandler and executes HLT to trigger it. The binary presents a dialog box asking for a serial number ('SERIAL:'). The .text section is RWX enabling self-modifying code, and the .rsrc section has entropy 85% indicating packed resources. FLOSS decoded 0 stack/tight strings (entire payload is bulk-encrypted). CAPA confirms XOR encoding (T1027/E1027.m02/C0026.002). Only 9 imports (GUI + SEH APIs) and 1 detected function (the stub) due to encrypted payload hiding all real logic. Additional coverage: Persistence: not observed; no evidence of mechanisms like registry keys or scheduled tasks for long-term execution. C2_network: not observed; no network activity or command-and-control communication indicators detected. Exfiltration: not observed; no data collection or exfiltration routines identified. Defense_impairment: observed; self-modifying code is enabled by RWX .text section (evidence: {summary, section properties, .text is RWX, allows dynamic code modification for evasion}) and bulk-encryption of payload impairs analysis (evidence: {FLOSS, string analysis, 0 stack strings decoded, hides malicious functionality from static tools}).

### deep key_evidence
- `"Entry stub at 0x401000: MOV EAX,0x4012b3; MOV ECX,0x5d8; XOR byte ptr [EAX],0x66; INC EAX; LOOP \u2192 bulk XOR decryption of 1496 bytes with key 0x66"`
- `"PUSH 0x4012b3 + PUSH 0x1 + CALL AddVectoredExceptionHandler \u2192 registers decrypted payload as first-chance VEH, then HLT triggers exception"`
- `"CAPA match: 'encode data using XOR' \u2192 MITRE T1027 Defense Evasion, MBC E1027.m02/C0026.002"`
- `"Malcat anomalies: SectionWX (.text RWX), SuspiciousEntropy (.rsrc 85% > 7.5 threshold), FewStrings (<1%), EntryOutsideSections"`
- `"FLOSS static strings: 'SERIAL:' (crackme password prompt), 'now this is getting serious', 'HEXORCIST CRACKME 7', 'Copyright SAS HEXORCIST'"`
- `"VersionInfo: FileDescription='HEXORCIST CRACKME 7', OriginalFilename='hexo7.EXE' \u2014 self-identifies as Hexorcist CTF challenge"`
- `"GUI imports: DialogBoxParamA, GetDlgItemTextA, MessageBoxA, EndDialog \u2014 typical crackme dialog interaction"`
- `"Only 1 function detected (entry stub, 30 bytes, 8 instructions) \u2014 all real logic hidden inside XOR-encrypted blob"`
- `"YARA hits: SEH__vectored (VEH patterns at offset 4238), contains_base64, IP/IPv6 patterns"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f
size: 141824
type: PE
architecture: X86
entrypoint_ea: 1024
entropy: 84
file_name: crackme7.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 33 | - |
| .text | 1024 | 2560 | 4096 | 77 | RWX |
| .bss | 5120 | 512 | 4096 | 0 | RW |
| .idata | 9216 | 512 | 4096 | 0 | RW |
| .data | 13312 | 512 | 4096 | 0 | RW |
| .rsrc | 17408 | 136704 | 139264 | 85 | R |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| FASM | compiler | INFO | 70 | detects fasm using DOS stub |

### Anomalies (4)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 8 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| FewStrings | 2 | strings | 0 | file does not have many identified strings (less than 1% of the file is composed of strings) |

### Anomaly Locations (high-signal)
- **XorInLoop**
  - `1034`: 

### High-Signal Strings (1 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 9276 | `KERNEL32.DLL` |

### Top Strings (139 extracted; showing 80)
| EA | String |
|---|---|
| 9276 | `KERNEL32.DLL` |
| 9290 | `USER32.DLL` |
| 13312 | `now this is getting serious` |
| 153612 | `hexo7.EXE` |
| 153178 | `VS_VERSION_INFO` |
| 153578 | `OriginalFilename` |
| 153306 | `040904E4` |
| 17686 | `HEXORCIST CRACKME 7` |
| 153440 | `Copyright SAS HEXORCIST` |
| 153364 | `HEXORCIST CRACKME 7` |
| 9358 | `AddVectoredExceptionHandler` |
| 153330 | `FileDescription` |
| 153270 | `StringFileInfo` |
| 153534 | `ProductVersion` |
| 2614 | `fffW` |
| 2600 | `fffW` |
| 2628 | `fffW` |
| 3012 | `fff`` |
| 2744 | `fffb` |
| 2569 | `fffe` |
| 2555 | `fffW` |
| 2642 | `fffe` |
| 2541 | `fffW` |
| 2527 | `fffW` |
| 3032 | `fffb` |
| 2496 | `fff`` |
| 2477 | `fff_` |
| 2448 | `fff`` |
| 3045 | `fffd` |
| 3065 | `fffb` |
| 3078 | `fffd` |
| 2408 | `fff`` |
| 2841 | `fffd` |
| 2940 | `fffd` |
| 2919 | `fffb` |
| 2952 | `fffb` |
| 2907 | `fffd` |
| 2886 | `fffb` |
| 2973 | `fffd` |
| 2874 | `fffd` |
| 2853 | `fffb` |
| 2660 | `fffd` |
| 2820 | `fffb` |
| 2808 | `fffd` |
| 2787 | `fffb` |
| 2326 | `fffW` |
| 2722 | `fffd` |
| 2696 | `fffd` |
| 2985 | `fffb` |
| 2678 | `fffd` |
| 3185 | `fffb` |
| 153670 | `Translation` |
| 153494 | `FileVersion` |
| 2086 | `fff`` |
| 2107 | `fff`` |
| 2128 | `fff`` |
| 2149 | `fff`` |
| 3198 | `fffd` |
| 2177 | `fff`` |
| 3095 | `fffb` |
| 2215 | `fffe` |
| 3168 | `fffd` |
| 2354 | `fffW` |
| 3108 | `fffd` |
| 3125 | `fffb` |
| 2368 | `fffe` |
| 2239 | `fffe` |
| 2340 | `fffW` |
| 3138 | `fffd` |
| 2295 | `fffd` |
| 2263 | `fffe` |
| 3155 | `fffb` |
| 77 | `!This program ca.. in DOS mode.
$` |
| 153410 | `LegalCopyright` |
| 17728 | `MS Sans Serif` |
| 2231 | `fffVn` |
| 13444 | `error` |
| 2255 | `fffVn` |
| 2207 | `fffVn` |
| 9476 | `GetDlgItemTextA` |

### Imports (9)
| EA | Name | Type | Refs |
|---|---|---|---|
| 9320 | kernel32.GetModuleHandleA | IMPORT | 1 |
| 9324 | kernel32.AddVectoredExceptionHandler | IMPORT | 1 |
| 9328 | kernel32.ExitProcess | IMPORT | 0 |
| 9428 | user32.DialogBoxParamA | IMPORT | 1 |
| 9432 | user32.GetDlgItemTextA | IMPORT | 0 |
| 9436 | user32.MessageBoxA | IMPORT | 0 |
| 9440 | user32.LoadIconA | IMPORT | 0 |
| 9444 | user32.SendMessageA | IMPORT | 0 |
| 9448 | user32.EndDialog | IMPORT | 0 |

### Functions (1)
| EA | Name |
|---|---|
| 1024 | EntryPoint |

### Decompilations (top 6)
#### 1024 — EntryPoint
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    uint8_t *puVar1;
    int32_t iVar2;
    
    puVar1 = 0x4012b3;
    iVar2 = 0x5d8;
    do {
        *puVar1 = *puVar1 ^ 0x66;
        puVar1 = puVar1 + 1;
        iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    (*kernel32.AddVectoredExceptionHandler)(1, 0x4012b3);
    do {
    /* WARNING: Do nothing block with infinite loop */
    } while( true );
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
| DLG/37/en-us | 232 | - |
| GRPICO/17/unk | 20 | - |
| VER/1/unk | 528 | - |

### Structures (29)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| ImportTable | 9216 |
| ImportNames | 9276 |
| kernel32.OFT | 9304 |
| kernel32.FT | 9320 |
| ImportNames | 9336 |
| user32.OFT | 9400 |
| user32.FT | 9428 |
| ImportNames | 9456 |
| Resources | 17408 |
| Resources.DLG | 17456 |
| Resources.DLG.37 | 17480 |
| Resources.GRPICO | 17504 |
| Resources.GRPICO.17 | 17528 |
| Resources.ICO | 17552 |
| Resources.ICO.1 | 17576 |
| Resources.VER | 17600 |
| Resources.VER.1 | 17624 |
| Resources.DLG.37.en-us | 17648 |
| Resources.DLG.37.en-us.Data | 17664 |
| Resources.ICO.1.unk | 17896 |
| Resources.ICO.1.unk.Data | 17912 |
| Resources.GRPICO.17.unk | 153120 |
| Resources.GRPICO.17.unk.Data | 153136 |
| Resources.VER.1.unk | 153156 |
| VersionInfo | 153172 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.79

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |

## PE Imports / Signals
import_count: 9

## YARA Matches (pipeline)
Total matches: 7

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@6508 len=2 |
| contains_base64 | - | $a@4218 len=16 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| FASM | - |  |
| SEH__vectored | - | $@4238 len=27 |

## Generated YARA Meta
```json
{
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe",
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
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 6508,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4218,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe",
      "strings": []
    },
    {
      "rule": "FASM",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe",
      "strings": []
    },
    {
      "rule": "SEH__vectored",
      "path": "/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe",
      "strings": [
        {
          "id": "$",
          "offset": 4238,
          "length": 27,
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
    "/opt/samples/rules/flat/Wshell_ChineseSpam.yar: error[E014]: invalid regular expression\n  --> /opt/samples/rules/flat/Wshell_ChineseSpam.yar:17:42\n   |\n17 |         $c = /if ?\\(\\$_POST\\[Submit\\]\\) ?{/\n   |                                          ^ unclosed counted repetit
```

## FLOSS Strings
Total strings: 33 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 33}`

### High-signal FLOSS
- `KERNEL32.DLL`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `.idata`
- `fffWjB`
- `KERNEL32.DLL`
- `USER32.DLL`
- `GetModuleHandleA`
- `AddVectoredExceptionHandler`
- `ExitProcess`
- `DialogBoxParamA`
- `GetDlgItemTextA`
- `MessageBoxA`
- `LoadIconA`
- `SendMessageA`
- `EndDialog`
- `now this is getting serious`
- `x0= 7*;1+,xhi!`
- `HEXORCIST CRACKME 7`
- `MS Sans Serif`
- `SERIAL:`
- `C&ancel`
- `VS_VERSION_INFO`
- `StringFileInfo`
- `040904E4`
- `FileDescription`
- `LegalCopyright`
- `Copyright SAS HEXORCIST`
- `FileVersion`
- `ProductVersion`
- `OriginalFilename`
- `hexo7.EXE`
- `VarFileInfo`
- `Translation`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401000
```asm
;-- section..text:
┌ 30: entry0 ();
│           0x00401000      b8b3124000     mov eax, 0x4012b3           ; [00] -rwx section size 4096 named .text
│           0x00401005      b9d8050000     mov ecx, 0x5d8              ; 1496
│       ┌─> 0x0040100a      803066         xor byte [eax], 0x66        ; [0x66:1]=255 ; 102
│       ╎   0x0040100d      40             inc eax
│       └─< 0x0040100e      e2fa           loop 0x40100a
│           0x00401010      68b3124000     push 0x4012b3
│           0x00401015      6a01           push 1                      ; 1
│           0x00401017      ff156c304000   call dword [sym.imp.KERNEL32.DLL_AddVectoredExceptionHandler] ; 0x40306c ; PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
└           0x0040101d      f4             hlt
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
  - `KERNEL32.DLL!AddVectoredExceptionHandler`
  - `KERNEL32.DLL!ExitProcess`
  - `USER32.DLL!DialogBoxParamA`
  - `USER32.DLL!GetDlgItemTextA`
  - `USER32.DLL!MessageBoxA`
  - `USER32.DLL!LoadIconA`
  - `USER32.DLL!SendMessageA`
