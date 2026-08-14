# Technical Evidence Pack

**sha256:** d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09  
**sample_path:** /opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 80
- **family_guess**: ransomware.lockbit
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple engines consistently detect packing via PECompact and high entropy. Import analysis across tools highlights dynamic resolution APIs (LoadLibrary, GetProcAddress) and memory allocation (VirtualAlloc), which are common in malware for payload execution. VirusTotal corroborates with high malicious detections and ransomware associations.
- **summary**: The sample 'want.exe' is packed with PECompact, exhibits high entropy (7.94), and has minimal imports focused on dynamic resolution and memory allocation. Key anomalies include executable/writable sections and unreferenced imports. VirusTotal detections (59 malicious) link it to Lockbit ransomware, indicating malicious intent beyond mere obfuscation. Behavioral indicators such as persistence and anti-debug tags further support the malicious verdict.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| packer_intake | packer_intake checks | `high_entropy_exec_section: true, few_imports: true` | Indicates packing with high entropy in executable sections and minimal imports, a common obfuscation technique that may  |
| pe_imports | imports | `load_library (LoadLibrary) and get_proc_address (GetProcAddress)` | Used for dynamic API resolution (MITRE T1129), which is a behavioral technique often employed by malware to evade static |
| malcat | anomalies | `SectionWX (executable and writable sections) and UnreferencedImports` | Executable and writable sections are suspicious as they may allow code modification in memory. Unreferenced imports sugg |
| yara | YARA rules | `PECompact and domain rules (e.g., PECompactV2XBitsumTechnologies, domain)` | Matching packer signatures confirms the sample is packed with PECompact, and domain rules may indicate C2 communication  |
| External TI | VirusTotal | `malicious detections (59) and threat class (ransomware.lockbit/delshad)` | High malicious score and association with ransomware provide strong external behavioral-intent evidence, aligning with l |
| malcat | file_summary | `entropy 7.94` | High entropy suggests encrypted or compressed data, which is common in packed malware to hide code and evade detection. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PECompact v2.x-packed Windows PE executable with strong indicators of malicious intent. The binary imports only 4 APIs — LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree — the minimal set required for runtime unpacking and dynamic API resolution, completely hiding the real payload. The .text section has high entropy (226/256 ≈ 0.88) indicating encrypted/compressed content. Both .text and .rsrc sections have RWX (Read-Write-Execute) permissions, characteristic of self-modifying unpacking stubs. Malcat detected 10 anomalies including invalid PE header fields, GUI subsystem without window APIs, large unreferenceable high-entropy data blocks (likely embedded crypto payloads), and section permission anomalies. Multiple YARA rules confirm PECompact packing by BitSum Technologies. The file size is 68KB with only a single 112-byte entry-point function visible, confirming the entire payload is packed. PE import signal analysis maps LoadLibrary/GetProcAddress to MITRE T1129 (Shared Module) and VirtualAlloc to T1055 (Process Injection). The actual malicious payload is entirely opaque to static analysis and would only execute at runtime after unpacking.

### deep key_evidence
- `"YARA: 10+ rules match PECompact v2.x packing (pecompact2, PECompact_2x_Jeremy_Collake, PECompactV2XBitsumTechnologies, etc.)"`
- `"Ghidra SQL imports: Only 4 imports \u2014 LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree \u2014 classic packer stub API set"`
- `"IDA SQL imports: Confirmed same 4 kernel32 imports at addresses 0x423990-0x42399C"`
- `"Ghidra SQL strings: Only 5 strings found (kernel32.dll + 4 import names), all payload strings encrypted"`
- `"IDA SQL strings: 411 strings detected but all are random/encrypted byte sequences (e.g., '}j0+', 'sZ]2@^w')"`
- `"Malcat anomalies: BigBufferNoXrefMediumToHighEntropy (3 hits) \u2014 large crypto data blocks with no cross-references"`
- `"Malcat anomalies: GuiSubsystemNoWindowApi \u2014 GUI PE with zero user32 window imports"`
- `"Malcat anomalies: InvalidSizeOfCode, InvalidSizeOfInitialDataSize, InvalidSizeOfUninitializedDataSize \u2014 PE header corruption from packing"`
- `"Malcat anomalies: HighEntropy (overall >200) \u2014 file entropy consistent with encrypted/compressed payload"`
- `"Malcat layout: .text section RWX (rights=RWX), .rsrc section RWX \u2014 writable executable sections enable runtime unpacking"`
- `"pe_import_signals: LoadLibrary\u2192T1129, GetProcAddress\u2192T1129, VirtualAlloc\u2192T1055 \u2014 dynamic API resolution and memory injection patterns"`
- `"Ghidra SQL funcs: Only 1 function (entry at 0x401000, 112 bytes) \u2014 entire codebase hidden inside packed blob"`
- `"YARA: contains_base64 rule matched at offset 63582 \u2014 encoded payload content detected"`
- `"File name: 'want.exe' \u2014 generic/social-engineering filename"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09
size: 68096
type: PE
architecture: X86
entrypoint_ea: 1024
entropy: 7.94
file_name: want.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 42 | - |
| .text | 1024 | 62464 | 163840 | 226 | RWX |
| .rsrc | 164864 | 4096 | 4096 | 0 | RWX |
| .reloc | 168960 | 512 | 4096 | 0 | RW |

### Malcat YARA / Signatures (4)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2017_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| visual_studio_2017_version_15_0_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| PECompact2 | packer | INFO | 60 | Detect PECompact based on section artifacts |
| pecompact_2xx | packer | INFO | 50 |  |

### Anomalies (10)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| MultiplePackers | 4 | packers | 1 | File is packed using multiple packers, very suspicious |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 3 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 4 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| Packed | 2 | packers | 1 | File is packed using a legit or less-legit obfuscator |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `324`: 

### High-Signal Strings (3 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 164940 | `kernel32.dll` |
| 164974 | `GetProcAddress` |
| 164958 | `LoadLibraryA` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 1052 | `mpact2` |
| 164940 | `kernel32.dll` |
| 77 | `!This program ca..in DOS mode.
$` |
| 33271 | `oj.FwT` |
| 41646 | `
:{T.KbA` |
| 164974 | `GetProcAddress` |
| 164958 | `LoadLibraryA` |
| 57474 | `VUgg` |
| 5264 | `wwRF` |
| 27725 | `d//i` |
| 5437 | `;6ZZ` |
| 2562 | `gqrg` |
| 30147 | `9\P9` |
| 26088 | `qq5?` |
| 42984 | `xM9M` |
| 43443 | `22<^` |
| 11613 | `JII1` |
| 37999 | `0mTT` |
| 50279 | `T@UT` |
| 164994 | `VirtualAlloc` |
| 165010 | `VirtualFree` |
| 19476 | `qqGf\` |
| 29941 | `es6sn` |
| 57277 | `KuHHf` |
| 480 | `.text` |
| 21800 | `vvH/=` |
| 13770 | `.]]W=` |
| 9262 | `hljlM` |
| 35535 | `47->>` |
| 520 | `.rsrc` |
| 46670 | `^l22` |
| 19713 | `2jDMM` |
| 49794 | `wmGeG<` |
| 41600 | `-mpLWm` |
| 6113 | `ye"%ey` |
| 45161 | `ZiZ_o/` |
| 9516 | `.BH2pKB` |
| 9013 | `JsHVHL` |
| 63038 | `/\k09k` |
| 24778 | `I3ueeO` |
| 27857 | `U0wU>1` |
| 45745 | `C2kA<9<J` |
| 167899 | `ApAlicat` |
| 46528 | `fhggR$;_` |
| 48306 | `Mw0qb`Y[4` |
| 24677 | `5;Hy^` |
| 10515 | `=-^9f` |
| 45150 | `5dIhO` |
| 11065 | `A6EDNc` |
| 44639 | `VWv-j` |
| 46036 | `wWKI?` |
| 44032 | `vq"l@` |
| 43998 | `0qMrd` |
| 19575 | `dxE9Rs` |
| 43370 | `[Y{Yb` |
| 42805 | `txg.j` |
| 42666 | `?ioA` |
| 42451 | `^Y:n4` |
| 12612 | `HuQ/P` |
| 46181 | `<bU
-x` |
| 24622 | `A>C.y` |
| 46983 | `s?8GWS` |
| 47527 | `chUH\` |
| 20066 | `I9=Dx` |
| 22214 | `gXKPV` |
| 21750 | `FlBdCb` |
| 8678 | `\_JQE6` |
| 20477 | `EChw@7>` |
| 48912 | `s:QM5` |
| 48923 | ``/F]\` |
| 49328 | `k?K/W` |
| 8478 | `q^4xDRa` |
| 8396 | `NV0XP` |
| 21070 | `fd/bt` |
| 33337 | `qkIWc
` |
| 37520 | `WXq#yW` |
| 14846 | `W7smc` |
| 36465 | `OF_oO(` |
| 35987 | `q&SDq` |
| 35934 | `Ah:lD` |

### Imports (4)
| EA | Name | Type | Refs |
|---|---|---|---|
| 164880 | kernel32.LoadLibraryA | IMPORT | 2 |
| 164884 | kernel32.GetProcAddress | IMPORT | 0 |
| 164888 | kernel32.VirtualAlloc | IMPORT | 0 |
| 164892 | kernel32.VirtualFree | IMPORT | 0 |

### Functions (2)
| EA | Name |
|---|---|
| 1024 | EntryPoint |
| 168332 | sub_429d8c |

### Decompilations (top 6)
#### 1024 — EntryPoint
```c
EntryPoint {
    // Error while decompiling : not a valid va
}

```
#### 168332 — sub_429d8c
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_429d8c(int32_t param_1)

{
    undefined *puVar1;
    
    [0x0x429db0] = 0xf0428b11;
    puVar1 = *(param_1 + 0xc);
    *puVar1 = 0xe9;
    *(puVar1 + 1) = 0x429daf - (puVar1 + 5);
    return 0;
}

```

### Structures (9)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 232 |
| OptionalHeader | 256 |
| Sections | 480 |
| kernel32.OFT | 164880 |
| ImportTable | 164900 |
| ImportNames | 164940 |
| Relocations | 168960 |


## capa Capability Rules
engine: `capa` · Total rules: 0 · duration_s: 0.94

| Rule | ATT&CK | MBC |
|---|---|---|

## PE Imports / Signals
import_count: 4

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 26

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| contains_base64 | - | $a@63582 len=12 |
| PECompactV2XBitsumTechnologies | - | $a0@1024 len=27 |
| PECompact2xxBitSumTechnologies | - | $a0@1024 len=35 |
| PECompactv2xx | - | $a0@1024 len=35 |
| pecompact2 | - | $str1@1024 len=27 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@208 len=4 |
| PeCompact_v208_Bitsum_Technologiessignature_by_loveboom | - | $a@1024 len=29 |
| PECompact_2x_Jeremy_Collake | - | $a@1024 len=27 |
| PECompact_20x_Heuristic_Mode_Jeremy_Collake | - | $a@1024 len=35 |
| PECompact_2xx_BitSum_Technologies | - | $a@1024 len=35 |
| PECompact_v2xx | - | $a@1024 len=35 |
| PECompact_V2X_Bitsum_Technologies_additional | - | $a@1024 len=27 |
| PECompact_V2X_Bitsum_Technologies | - | $a@1024 len=27 |
| PECompact_v20_additional | - | $a@1024 len=29 |
| PeCompact_2xx_BitSum_Technologies | - | $a@1024 len=35 |
| PeCompact_253_DLL_BitSum_Technologies_additional | - | $a@1024 len=35 |
| PECompact_v20 | - | $a@1024 len=29; $b@1024 len=35 |
| PeCompact_253_DLL_BitSum_Technologies | - | $a@1024 len=35 |
| PECompact_v2xx_additional | - | $a@1024 len=35 |
| suspicious_packer_section | - |  |
| SEH_Save | - | $a@1030 len=7 |
| SEH_Init | - | $b@1037 len=7 |

## Generated YARA Meta
```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 63582,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompactV2XBitsumTechnologies",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 1024,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact2xxBitSumTechnologies",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 1024,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompactv2xx",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 1024,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "pecompact2",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$str1",
          "offset": 1024,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
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
      "rule": "PeCompact_v208_Bitsum_Technologiessignature_by_loveboom",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1024,
          "length": 29,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact_2x_Jeremy_Collake",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1024,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact_20x_Heuristic_Mode_Jeremy_Collake",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1024,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PECompact_2xx_BitSum_Technologies",
      "path": "/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe",
      "strings": [
        {
          "id"
```

## FLOSS Strings
Total strings: 148 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 148}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `.reloc`
- `PECompact2`
- `T5K;	V`
- `sZ]2@^w`
- `dMe!p/`
- `@b*!.>`
- `@Qd]w+A`
- `hUDf&A4`
- `pWC7kl`
- ``J L5''m`
- `(3FcewM`
- `TA-rD,`
- `nmsA.r`
- `@)*)][`
- `d2*wnC5`
- `MKX/s0`
- `^ /c_j`
- `}Dgt|(`
- `(./m)j`
- `ye"%ey`
- `=3OD4X`
- `q,Gdg+`
- `6|e0kg`
- `P1%4CO`
- `u&)b	9`
- `q^4xDRa`
- `\_JQE6`
- `JsHVHL`
- `.BH2pKB`
- `~D&y2$`
- `i}feR5`
- `PXg+j~k`
- `A6EDNc`
- `tE	,K&`
- `(.D|"b`
- `#L6@2'}!`
- `nOPmlH\`
- `^rh2pR`
- `{CRnB3`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401000
```asm
;-- section..text:
┌ 114: entry0 ();
│           0x00401000      b88c9d4200     mov eax, 0x429d8c           ; [00] -rwx section size 163840 named .text
│           0x00401005      50             push eax
│           0x00401006      64ff350000..   push dword fs:[0]
│           0x0040100d      6489250000..   mov dword fs:[0], esp
│           0x00401014      33c0           xor eax, eax
│           0x00401016      8908           mov dword [eax], ecx
│           0x00401018      50             push eax
│           0x00401019      45             inc ebp
│           0x0040101a      43             inc ebx
│           0x0040101b      6f             outsd dx, dword [esi]
│           0x0040101c      6d             insd dword es:[edi], dx
│       ┌─< 0x0040101d      7061           jo 0x401080
│       │   0x0040101f      63743200       arpl word [edx + esi], si
│     ╎╎│   0x00401023      bc794e9e74     mov esp, 0x749e4e79
│     ╎╎│   0x00401028      47             inc edi
│     ╎╎│   0x00401029      0300           add eax, dword [eax]
│     ╎╎│   0x0040102b      81903c9304..   adc dword [eax + 0xd04933c], 0xd8418213
│     ╎╎│   0x00401035      3eaf           scasd eax, dword es:[edi]
│     ╎╎│   0x00401037      0e             push cs
│    ┌────< 0x00401038      ea8deb171c..   ljmp 0x2ff
..
│  │ │  └─> 0x00401080      646c           insb byte es:[edi], dx
│  │ │      0x00401082      e23e           loop 0x4010c2
│  │ │      0x00401084      f5             cmc
│  │ │      0x00401085      d28ac6e262e4   ror byte [edx - 0x1b9d1d3a], cl
│  │ │      0x0040108b      68b75856e3     push 0xe35658b7
│  │ │      0x00401090      2c67           sub al, 0x67                ; 103
│  │ │      0x00401092      f9             stc
│  │ │      0x00401093      3c55           cmp al, 0x55                ; 'U' ; 85
│  │ │      0x00401095      16             push ss
│  │ │      0x00401096      2dabf2e4cb     sub eax, 0xcbe4f2ab
│  │ │      0x0040109b      b153           mov cl, 0x53                ; 'S' ; 83
│  │ │      0x0040109d      bf1e381a34     mov edi, 0x341a381e         ; '\x1e8\x1a4'
│  │ │      0x004010a2      98             cwde
│  │ │      0x004010a3      c226d7         ret 0xd726
..
│  │ │      0x004010ae      ac             lodsb al, byte [esi]
│  └──────> 0x004010af      0284fd79c1..   add al, byte [ebp + edi*8 + 0x2faec179]
│    │      0x004010b6      ff             invalid
..
│    │      0x004010c2      e3ea           jecxz 0x4010ae
│    │      0x004010c4      58             pop eax
└    │      0x004010c5      8d             invalid
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
  - `kernel32.dll!LoadLibraryA`
  - `kernel32.dll!GetProcAddress`
  - `kernel32.dll!VirtualAlloc`
  - `kernel32.dll!VirtualFree`
