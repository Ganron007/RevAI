# Technical Evidence Pack

**sha256:** 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96  
**sample_path:** /opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 90
- **family_guess**: Satana ransomware
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA both report 28 functions, indicating consistent analysis. MalCat provides static anomalies like XorInLoop and BigBufferNoXrefMediumToHighEntropy, suggesting obfuscation and crypto data. Capa detects anti-VM strings for sandbox evasion, and YARA matches a ransomware dropper rule. VirusTotal corroborates with 67 malicious detections and ransomware threat category. FLOSS strings include base64-encoded data and sensitive APIs for memory manipulation.
- **summary**: The sample is malicious with high confidence. Key indicators include YARA rule match for ransomware dropper, capa detection of anti-VM evasion, and VirusTotal's widespread malicious detections. Anomalies like XOR loops and base64 strings point to obfuscation and encryption routines, while FLOSS-revealed APIs suggest memory manipulation for malicious purposes. Behavioral signals such as sandbox evasion and environment detection confirm hostile intent beyond mere obfuscation.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | Ransom_Satana_Dropper | `Ransom_Satana_Dropper` | Direct YARA match for known ransomware dropper signature, indicating malicious intent to deliver ransomware payload. |
| capa | reference anti-VM strings targeting Qemu | `reference anti-VM strings targeting Qemu` | Shows sandbox evasion behavior, a behavioral-intent tactic to avoid detection in analysis environments. |
| malcat | anomalies | `XorInLoop` | XOR instructions in loops suggest encryption or obfuscation routines, commonly used in malware for hiding payloads or da |
| virustotal | threat_class | `popular_threat_category ransomware` | VirusTotal identifies high malicious detections (67) with ransomware as a top category, supporting malicious classificat |
| floss | strings | `ZwProtectVirtualMemory, NtAllocateVirtualMemory` | APIs for virtual memory manipulation, often used in process injection or shellcode execution, indicating potential malic |
| malcat | decompilations | `sub_401e60` | Function accesses PEB via PEBx86, a common technique for environment detection and anti-analysis in malware. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Satana ransomware dropper with extensive anti-analysis capabilities. The sample matches the Ransom_Satana_Dropper YARA rule with 3 string signatures, contains anti-debugging (ZwGetContextThread, OutputDebugStringA, NtYieldExecution, 4 TLS callbacks executing before entry point), anti-VM/Qemu detection, a massive encoded payload blob with embedded URLs and IPv6 addresses, a Base64 encoding table, and highly obfuscated control flow (cyclomatic complexity 91 in main function). OpenGL API imports (11 functions) serve as anti-sandbox evasion. The dropper contains obfuscated configuration and C2 infrastructure. Persistence mechanisms: not observed. Exfiltration mechanisms: not observed.

### deep key_evidence
- `"YARA rule 'Ransom_Satana_Dropper' matched with 3 strings at offsets 1264, 1628, 1196 \u2014 direct family identification"`
- `"YARA rule 'anti_dbg' matched with 2 strings at offsets 690 and 9350 \u2014 anti-debugging techniques present"`
- `"YARA rule 'Qemu_Detection' matched at offset 44611 \u2014 anti-VM/sandbox evasion"`
- `"YARA rule 'url' matched at offset 49141 (53 chars) \u2014 embedded URL for C2 or ransom payment"`
- `"YARA rule 'IP' (IPv6) matched at offset 22282 \u2014 embedded network indicators"`
- `"YARA rules 'contains_base64' and 'BASE64_table' matched \u2014 encoded payload detected"`
- `"Ghidra string_refs: 4 TLS callbacks (First_tls, on_tls_callback1, on_tls_callback2, on_tls_callback3) \u2014 code executes before entry point, anti-debugging technique"`
- `"Ghidra imports: ZwGetContextThread from NTDLL.DLL \u2014 anti-debugging (checks debug context registers)"`
- `"Ghidra imports: OutputDebugStringA from KERNEL32.DLL \u2014 known anti-debugging technique"`
- `"Ghidra imports: NtYieldExecution from NTDLL.DLL \u2014 anti-debugging/anti-analysis"`
- `"Ghidra imports: 11 OpenGL functions (glBegin, glClear, glColor3d, glVertex3d, etc.) from OPENGL32.DLL \u2014 unusual for non-GUI PE, anti-sandbox technique"`
- `"Ghidra function_metrics: FUN_00401310 has cyclomatic_complexity=91, block_count=91, instruction_count=486, size=2349 \u2014 highly complex obfuscated logic"`
- `"Ghidra strings: obfuscated string 'qfntvthb' referenced by FUN_00402030 \u2014 likely encoded key or config"`
- `"Ghidra strings: massive encoded blob (thousands of chars, non-ASCII) at address 0x401B00+ \u2014 encrypted/obfuscated payload or configuration"`
- `"Malcat static profile: entropy 135, anomalies count 7, file size 50861 \u2014 high entropy consistent with packed/encrypted content"`
- `"YARA rule 'Safeguard_103_Simonzh' matched at offset 6416 \u2014 additional malware family signature"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96
size: 50861
type: PE
architecture: X86
entrypoint_ea: 6416
entropy: 6.46
file_name: drtg.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 52 | - |
| .text | 1024 | 8704 | 12288 | 124 | RX |
| .data | 13312 | 38912 | 40960 | 144 | RW |
| .rsrc | 54272 | 1024 | 4096 | 89 | R |
| .reloc | 58368 | 1024 | 4096 | 19 | R |
| overlay | 62464 | 173 | 0 | 170 | - |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2010_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |

### Anomalies (7)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| RichMultipleLinkers | 3 | rich | 1 | multiple linker entries in rich header |
| StringBase64 | 3 | strings | 1 | string has more than 16 characters is encoded using base64 |
| WeirdDebugInfoType | 3 | headers | 1 | the Debug infos are not in the usual format |
| XorInLoop | 3 | code | 11 | XOR instruction in a loop |
| BoundImports | 2 | imports | 1 | Bound imports are present |

### Anomaly Locations (high-signal)
- **ManyUniqueImmediateBytes**
  - `4176`: 
- **XorInLoop**
  - `4361`: 
  - `4422`: 
  - `4454`: 
  - `4546`: 
  - `4598`: 

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 690 | `KERNEL32.dll` |
| 9370 | `KERNEL32.dll` |

### Top Strings (141 extracted; showing 80)
| EA | String |
|---|---|
| 51272 | `ABCDEFGHIJKLMNOP..wxyz0123456789+/` |
| 13552 | `5rhQJGe:aT6waT1W..BBBBBBBBBBBBBBBB` |
| 54360 | `<assembly xmlns=..XPADDINGPADDINGX` |
| 1236 | `MyUnhandledExceptionFilter` |
| 1480 | `333333` |
| 1332 | `on_tls_callback1` |
| 1216 | `ZwGetContextThread` |
| 1320 | `First_tls` |
| 1208 | `.dll` |
| 680 | `ntdll.dll` |
| 9322 | `ntdll.dll` |
| 1372 | `on_tls_callback3` |
| 1352 | `on_tls_callback2` |
| 1196 | `qfntvthb` |
| 1280 | `EntryPoint` |
| 690 | `KERNEL32.dll` |
| 9370 | `KERNEL32.dll` |
| 9548 | `OPENGL32.dll` |
| 9398 | `USER32.dll` |
| 714 | `OPENGL32.dll` |
| 703 | `USER32.dll` |
| 1264 | `%s-TryExcept` |
| 1312 | `%s-4` |
| 1304 | `%s-3` |
| 1296 | `%s-2` |
| 1628 | `d:\lbetwmwy\uijeuqplfwub.pdb` |
| 50622 | `jmenfrhmjebkjhainycnyvrdfclb` |
| 1487 | `@ffffff
@` |
| 77 | `!This program ca..in DOS mode.
$` |
| 58823 | `6"6>6I6N6S6` |
| 1399 | `@ffffff` |
| 1415 | `?333333` |
| 58561 | `:!:/:J:X:e:m:y:` |
| 51638 | `bapbjfrknvrsmfmrn` |
| 9274 | `memmove` |
| 51730 | `ehjegborhilopxmydycpasir` |
| 58677 | `081L1Y1^1i1v1~1` |
| 58383 | `3$30363C3Z3j3{3` |
| 58723 | `2$2)2=2E2V2`2t2` |
| 58589 | `;,;H;S;c;o;` |
| 58411 | `4*424>4\4w4` |
| 51438 | `kyhtwlttycl` |
| 58435 | `5&525=5[5v5` |
| 58459 | `6(606<6Z6u6` |
| 58485 | `7,747@7^7y7` |
| 9350 | `OutputDebugStringA` |
| 58507 | `7	868D8Q8Y8e8p8{8` |
| 58613 | `<*<5<@<O=X=R>j>o>` |
| 9458 | `glLineStipple` |
| 58851 | `8#8(8I8d8i8w8` |
| 51774 | `fxpusugcfbhgdacizktsh` |
| 9508 | `glPolygonMode` |
| 58635 | `>B?N?`?f?` |
| 50901 | `hcqzqdnqhvfbsrryd` |
| 9564 | `memset` |
| 58805 | `5!5&505I5U5` |
| 58535 | `8
949B9Q9~9` |
| 51139 | `uqvgoieyrqolhevswzxu` |
| 51200 | `YGI@GGV` |
| 51545 | `nrxqlxmdujmn` |
| 51688 | `tuwhzxcunkawcvsamcb` |
| 1150 | `kaxkytpp` |
| 51512 | `wrawfeeh` |
| 51078 | `yaqrbysjaqmdw` |
| 9284 | `NtYieldExecution` |
| 58761 | `3$3)3M3k3` |
| 9496 | `glColor3d` |
| 58793 | `4$4*4B4_4` |
| 58891 | `:!;9;I;[;` |
| 13317 | `DfGmmxhAmp` |
| 50925 | `rPc@P`__TF` |
| 50977 | `wemzgrdwugjw` |
| 51101 | `hMTmQVK@FTFdIJ` |
| 13339 | `qwvywvszdcvle` |
| 50689 | `@bMrbRmmft` |
| 9386 | `MessageBoxA` |
| 13361 | `Veu[qljtotrrP` |
| 58947 | `>B?G?` |
| 51765 | `CS[S^` |
| 50821 | `mypvm` |

### Constants / Known Patterns (2)
| Category | Value |
|---|---|
| code | `code::PEBx86` |
| crypto | `crypto::Base64` |

### Imports (21)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1024 | kernel32.GetLocalTime | IMPORT | 8 |
| 1028 | kernel32.OutputDebugStringA | IMPORT | 1 |
| 1036 | opengl32.glEnd | IMPORT | 10 |
| 1040 | opengl32.glEnable | IMPORT | 4 |
| 1044 | opengl32.glLineWidth | IMPORT | 4 |
| 1048 | opengl32.glPolygonMode | IMPORT | 3 |
| 1052 | opengl32.glColor3d | IMPORT | 1 |
| 1056 | opengl32.glBegin | IMPORT | 1 |
| 1060 | opengl32.glDisable | IMPORT | 4 |
| 1064 | opengl32.glClear | IMPORT | 1 |
| 1068 | opengl32.glPointSize | IMPORT | 3 |
| 1072 | opengl32.glLineStipple | IMPORT | 1 |
| 1076 | opengl32.glVertex3d | IMPORT | 1 |
| 1084 | user32.MessageBoxA | IMPORT | 2 |
| 1092 | ntdll.vsprintf | IMPORT | 2 |
| 1096 | ntdll.memmove | IMPORT | 1 |
| 1100 | ntdll.NtYieldExecution | IMPORT | 1 |
| 1104 | ntdll.strchr | IMPORT | 1 |
| 1108 | ntdll.strncpy | IMPORT | 1 |
| 1112 | ntdll._stricmp | IMPORT | 1 |
| 1116 | ntdll.memset | IMPORT | 1 |

### Functions (29)
| EA | Name |
|---|---|
| 4704 | sub_401e60 |
| 5136 | sub_402010 |
| 1712 | PEBx86 |
| 4176 | sub_401c50 |
| 6672 | sub_402610 |
| 5168 | sub_402030 |
| 8816 | sub_402e70 |
| 8352 | sub_402ca0 |
| 7952 | sub_402b10 |
| 1664 | sub_401280 |
| 8224 | sub_402c20 |
| 1728 | sub_4012c0 |
| 1808 | sub_401310 |
| 7488 | sub_402940 |
| 1744 | sub_4012d0 |
| 1696 | sub_4012a0 |
| 7232 | sub_402840 |
| 4158 | jmp_ntdll.memset |
| 6416 | EntryPoint |
| 7312 | sub_402890 |
| 6608 | sub_4025d0 |
| 6432 | sub_402520 |
| 6256 | sub_402470 |
| 6512 | sub_402570 |
| 8560 | sub_402d70 |
| 6208 | sub_402440 |
| 8176 | sub_402bf0 |
| 7221 | sub_402835 |
| 7296 | sub_402880 |

### Decompilations (top 6)
#### 4704 — sub_401e60
```c

/* WARNING: Removing unreachable block (ram,0x00401fb1) */
/* WARNING: Removing unreachable block (ram,0x00401ef3) */
/* WARNING: Removing unreachable block (ram,0x00401ef5) */
/* WARNING: Removing unreachable block (ram,0x00401ee4) */
/* WARNING: Removing unreachable block (ram,0x00401ee6) */
/* WARNING: Removing unreachable block (ram,0x00401ebf) */
/* WARNING: Removing unreachable block (ram,0x00401f10) */
/* WARNING: Removing unreachable block (ram,0x00401fbb) */
/* WARNING: Removing unreachable block (ram,0x00401ec4) */
/* WARNING: Restarted to delay deadcode elimination for space: stack */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401e60(void)

{
    uint32_t uVar1;
    uint32_t uStack_8;
    
    sub_4012d0(0x40110c, "First_tls");
    uVar1 = [0x0x401064];
    [0x0x40d594] = 0;
    if (([0x0x40d41c] == 0) && ([0x0x401064] != 0)) {
        uStack_8 = 0;
        do {
            uStack_8 = uStack_8 + 1;
        } while (uStack_8 < 0xfaa7c);
        0040d668 = PEBx86();
        if (0040d668 != 0) {
            0040d41c = *(0040d668 + 0x30);
            uStack_8 = 0;
            if ((uVar1 >> 0x10) + ([0x0x401064] & 0xffff) * 2 != 0) {
                do {
                    uStack_8 = uStack_8 + 1;
                } while (uStack_8 < (uVar1 >> 0x10) + ([0x0x401064] & 0xffff) * 2);
            }
            if (0040d41c != 0) {
                sub_402520();
                return;
            }
            func_0x0040103c();
        }
    }
    return;
}

```
#### 5136 — sub_402010
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_402010(void)

{
    int32_t iVar1;
    
    iVar1 = 0;
    do {
        *((&Base64)[iVar1] + 0x40d6a8) = iVar1;
        iVar1 = iVar1 + 1;
    } while (iVar1 < 0x40);
    return;
}

```
#### 1712 — PEBx86
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 PEBx86(void)

{
    int32_t unaff_FS_OFFSET;
    
    return *(unaff_FS_OFFSET + 0x18);
}

```

### Virtual Files (1)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| MANIF/1/en-us | 607 | - |

### Structures (25)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 232 |
| OptionalHeader | 256 |
| Sections | 480 |
| BoundImportTable | 640 |
| BoundImportNames | 680 |
| kernel32.FT | 1024 |
| opengl32.FT | 1036 |
| user32.FT | 1084 |
| ntdll.FT | 1092 |
| DebugDirectory | 1168 |
| Debug.Fixup | 1604 |
| ImportTable | 9048 |
| kernel32.OFT | 9148 |
| opengl32.OFT | 9160 |
| user32.OFT | 9208 |
| ntdll.OFT | 9216 |
| ImportNames | 9248 |
| Resources | 54272 |
| Resources.MANIF | 54296 |
| Resources.MANIF.1 | 54320 |
| Resources.MANIF.1.en-us | 54344 |
| Manifest | 54360 |
| Relocations | 58368 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 7 · duration_s: 0.89

| Rule | ATT&CK | MBC |
|---|---|---|
| reference Base64 string | T1027:Obfuscated Files or Information | C0026.001:Encode Data, C0019:Check String |
| reference anti-VM strings targeting Qemu | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| inspect section memory permissions |  | B0046.002:Code Discovery |
| parse PE header | T1129:Shared Modules |  |
| contains PDB path |  |  |
| print debug messages |  |  |
| resolve function by parsing PE exports |  |  |

## PE Imports / Signals
import_count: 21

## YARA Matches (pipeline)
Total matches: 15

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@22282 len=3 |
| contains_base64 | - | $a@1216 len=16 |
| Qemu_Detection | - | $a0@44611 len=4 |
| BASE64_table | - | $c0@47688 len=64 |
| url | - | $url_regex@49141 len=53 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@200 len=4 |
| Safeguard_103_Simonzh | - | $a@6416 len=5 |
| Check_OutputDebugStringA_iat | - |  |
| anti_dbg | - | $d1@690 len=12; $c3@9350 len=17 |
| Ransom_Satana_Dropper | - | $a@1264 len=12; $b@1628 len=28; $c@1196 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 22282,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1216,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Qemu_Detection",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 44611,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "BASE64_table",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 47688,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 49141,
          "length": 53,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 200,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Safeguard_103_Simonzh",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 6416,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Check_OutputDebugStringA_iat",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 690,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 9350,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Ransom_Satana_Dropper",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/
```

## FLOSS Strings
Total strings: 145 · per_category: `{"decoded_strings": 15, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 130}`

### High-signal FLOSS
- `KERNEL32.dll`

### FLOSS sample
- `ZwProtectVirtualMemory`
- `ZwWriteVirtualMemory`
- `GetModuleFileNameW`
- `FlushInstructionCache`
- `ZwUnmapViewOfSection`
- `4siPKFd;`U7v`U0VcPGjirHv`fWPIVuSGQ2TISePjPGf[1KP30Lv0UQeVLWP`AEeVFiD@@6PVP2dCemdFCCPVS6OCuOAEW2PFujLJzeFVSSPC22rKh7LCCIPASjF[E@lQPUZ`
- `NtAllocateVirtualMemory`
- `?456789:;<=`
- `!"#$%&'()*+,-./0123`
- `SetUnhandledExceptionFilter`
- `RtlDecompressBuffer`
- `!This program cannot be run in DOS mode.`
- ``.data`
- `@.reloc`
- `ntdll.dll`
- `KERNEL32.dll`
- `USER32.dll`
- `OPENGL32.dll`
- `kaxkytpp`
- `qfntvthb`
- `ZwGetContextThread`
- `MyUnhandledExceptionFilter`
- `%s-TryExcept`
- `EntryPoint`
- `First_tls`
- `on_tls_callback1`
- `on_tls_callback2`
- `on_tls_callback3`
- `@ffffff`
- `?333333`
- `333333`
- `d:\lbetwmwy\uijeuqplfwub.pdb`
- `YUSW_[]`
- `^SP@X[Q=`
- `QSVWh(`
- `Rj@ZZQ}`
- `Ilz`_R`
- `UWRjyZZ_]PP|`
- `_P@XUf`
- `UjS]]f`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00402510
```asm
┌ 11: entry0 ();
│           0x00402510      e8fb000000     call fcn.00402610
│           0x00402515      a164104000     mov eax, dword [0x401064]   ; [0x401064:4]=0x5de7afeb
└           0x0040251a      c3             ret
```
### 0x00402610
```asm
; CALL XREF from entry0 @ 0x402510(x)
┌ 549: fcn.00402610 ();
│           ; var int32_t var_4h @ esp+0xc
│           ; var int32_t var_8h @ esp+0x24
│           ; var int32_t var_10h @ esp+0x28
│           0x00402610      8bff           mov edi, edi
│           0x00402612      55             push ebp
│           0x00402613      8bec           mov ebp, esp
│           0x00402615      83e4f8         and esp, 0xfffffff8
│           0x00402618      83ec14         sub esp, 0x14
│           0x0040261b      56             push esi
│           0x0040261c      6800114000     push 0x401100               ; "EntryPoint"
│           0x00402621      680c114000     push 0x40110c               ; '\f\x11@' ; "%s"
│           0x00402626      e8a5ecffff     call 0x4012d0
│           0x0040262b      83c408         add esp, 8
│           0x0040262e      e84decffff     call 0x401280
│           0x00402633      85c0           test eax, eax
│       ┌─< 0x00402635      7416           je 0x40264d
│       │   0x00402637      8d442408       lea eax, [var_8h]
│       │   0x0040263b      50             push eax
│       │   0x0040263c      ff1500104000   call dword [sym.imp.KERNEL32.dll_GetLocalTime] ; 0x401000 ; "1H\x02" ; VOID GetLocalTime(LPSYSTEMTIME lpSystemTime)
│       │   0x00402642      0fb74c2410     movzx ecx, word [var_10h]
│       │   0x00402647      890d94d54000   mov dword [0x40d594], ecx   ; [0x40d594:4]=0
│       └─> 0x0040264d      6800114000     push 0x401100               ; "EntryPoint"
│           0x00402652      6810114000     push 0x401110               ; '\x10\x11@' ; "%s-2"
│           0x00402657      e874ecffff     call 0x4012d0
│           0x0040265c      83c408         add esp, 8
│           0x0040265f      e8acecffff     call 0x401310
│           0x00402664      6a72           push 0x72                   ; 'r' ; 114
│           0x00402666      e8d5010000     call 0x402840
│           0x0040266b      b838ebf906     mov eax, 0x6f9eb38
│       ┌─> 0x00402670      52             push edx
│       ╎   0x00402671      51             push ecx
│      ┌──< 0x00402672      7c03           jl 0x402677
│      │╎   0x00402674      660bc0         or ax, ax
│      └──> 0x00402677      59             pop ecx
│       ╎   0x00402678      5a             pop edx
│       ╎   0x00402679      45             inc ebp
│       ╎   0x0040267a      4d             dec ebp
│       ╎   0x0040267b      80c000         add al, 0
│       ╎   0x0040267e      81fb46c98d5b   cmp ebx, 0x5b8dc946
│       ╎   0x00402684      55             push ebp
│       ╎   0x00402685      83c600         add esi, 0
│       ╎   0x00402688      5d             pop ebp
│       ╎   0x00402689      f6d6           not dh
│       ╎   0x0040268b      f6d6           not dh
│       ╎   0x0040268d      8bff           mov edi, edi
│       ╎   0x0040268f      46             inc esi
│       ╎   0x00402690      4e             dec esi
│      ┌──< 0x00402691      7308           jae 0x40269b
│      │╎   0x00402693      55  
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r

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
  - `ntdll.dll!vsprintf`
  - `ntdll.dll!memmove`
  - `ntdll.dll!NtYieldExecution`
  - `ntdll.dll!strchr`
  - `ntdll.dll!strncpy`
  - `KERNEL32.dll!GetLocalTime`
  - `KERNEL32.dll!OutputDebugStringA`
  - `USER32.dll!MessageBoxA`
  - `OPENGL32.dll!glEnd`
  - `OPENGL32.dll!glEnable`
  - `OPENGL32.dll!glLineWidth`
  - `OPENGL32.dll!glPolygonMode`
  - `OPENGL32.dll!glColor3d`
