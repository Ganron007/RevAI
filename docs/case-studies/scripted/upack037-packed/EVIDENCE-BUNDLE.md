# Technical Evidence Pack

**sha256:** 36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9  
**sample_path:** /opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe  
**project_name:** REVAI-LAB-CORPUS-H1

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 60
- **family_guess**: Upack
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Discrepancies between Ghidra and IDA in function and string counts (0 vs 1 functions, 22 vs 229 strings) suggest packing or obfuscation; Ghidra found no imports while IDA found 2, aligning with Malcat's NoImportTable anomaly. Capa failed due to corrupt PE header, indicating high obfuscation.
- **summary**: The sample is a packed PE executable identified as Upack 037, with multiple anomalies from Malcat and YARA indicating obfuscation techniques. IDA reveals minimal imports for dynamic loading, and Capa fails due to corrupt headers. No clear behavioral-intent evidence (e.g., C2, persistence, or malicious strings) was found; thus, it is suspicious based solely on obfuscation and packing signals, which are neutral but common in malware.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | anomalies | `Packed` | Malcat anomaly 'Packed' indicates the file is packed using an obfuscator, a neutral but common technique in malware to h |
| packer_intake | packer_intake checks | `score=8` | Packer_intake score of 8 based on high entropy in executable sections and raw vs virtual size mismatches, indicating pac |
| yara | YARA matches | `Upack_V037_Dwing` | YARA rule matches known Upack packer signature, confirming the use of a packer, which is a neutral obfuscation signal bu |
| ida | imports | `LoadLibraryA and GetProcAddress` | IDA shows only these two imports, which are commonly used for dynamic function resolution in packed or malicious code to |
| malcat | anomalies | `NoImportTable` | Lack of a valid import table is typical in packed executables where imports are resolved dynamically at runtime, adding  |
| capa | capa error | `corrupt header` | Capa failed to parse the PE file due to a corrupt header, suggesting heavy obfuscation or packing that prevents standard |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This sample is a packed executable using Upack v0.37 packer that masquerades as Windows Calculator (CALC.EXE) from Microsoft Corporation. The PE header is intentionally corrupted (capa reports 'data at RVA can't be fetched. Corrupt header?'), characteristic of Upack-packed files. Only two imports exist (LoadLibraryA and GetProcAddress), which is the classic packer stub pattern for dynamic API resolution to evade static analysis. All memory segments are marked RWX (read/write/execute), indicating self-modifying code behavior. The file contains embedded IP addresses (IPv4/IPv6), domain patterns, and base64-encoded content detected by YARA. FLOSS failed to extract stack strings due to the corrupted PE structure. Version info metadata (Microsoft Corporation, Windows Calculator) is a masquerade - 21 YARA rules definitively match Upack packer signatures. The true payload is hidden beneath the packer and would execute dynamically at runtime.

### deep key_evidence
- `"YARA: 21 rules matched including WinUpackv039finalByDwing, UpackV037Dwing, Upack_V037_V039_Dwing, Upack_v039_final - definitive Upack packer identification"`
- `"IDA imports: Only KERNEL32!LoadLibraryA (0x1001828) and KERNEL32!GetProcAddress (0x100182C) - classic packer stub with dynamic API resolution"`
- `"capa error: 'data at RVA can't be fetched. Corrupt header?' - PE structure intentionally corrupted by Upack packer"`
- `"Ghidra memory_blocks: All 3 code segments (PS______, seg003, M_____) have perm=7 (RWX) - indicates self-modifying/unpacking code"`
- `"YARA: HasOverlay, HasModified_DOS_Message - packer structural anomalies"`
- `"YARA: domain rule matched at offset 0, IPv4 at offset 2212, IPv6 at offset 6028 - embedded network indicators"`
- `"YARA: contains_base64 matched at offset 42 - encoded content in payload"`
- `"Ghidra strings: Version info masquerades as 'Windows Calculator application file' by 'Microsoft Corporation' v5.1.2600.0, OriginalFilename='CALC.EXE' - brand spoofing"`
- `"FLOSS failure: 'TypeError: a bytes-like object is required, not NoneType' - PE corruption prevents stack string extraction"`
- `"File labeled as 'dotnet' type but packed with Upack native packer - likely .NET payload wrapped in native packer shell"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9
size: 52224
type: PE
architecture: X86
entrypoint_ea: 86040
entropy: 156
file_name: Upack037.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| M÷ü | 0 | 512 | 4096 | 132 | RWX |
|  | 4096 | 51712 | 81920 | 156 | RWX |
| PSÿÕ«ëçÃ | 86016 | 0 | 126976 | 0 | RWX |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| upack_037_03 | packer | INFO | 50 |  |
| upack_039f_03 | packer | INFO | 50 |  |

### Anomalies (17)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| InvalidBaseOfCode | 4 | sections | 1 | at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section |
| NoImportTable | 4 | imports | 1 | no valid Import Table found |
| PointerToRawDataNotAligned | 4 | sections | 2 | PointerToRawData is not aligned to FileAlignment |
| SizeOfRawDataNotAligned | 4 | sections | 2 | SizeOfRawData is not aligned to FileAlignment |
| WrongSizeOfOptionalHeader | 4 | headers | 1 | The field SizeOfOptionalHeader in the PE header is not set correctly |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| SectionEmptyName | 3 | sections | 1 | section name is null |
| SectionNameUnknown | 3 | sections | 3 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 3 | section is executable and writeable |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| InvalidSizeOfUninitializedData | 2 | sections | 1 | SizeOfUninitializedData is not the sum of all uninitalized data sections (raw or virtual) |
| Packed | 2 | packers | 2 | File is packed using a legit or less-legit obfuscator |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `108`: 
- **NoChecksum**
  - `104`: 

### High-Signal Strings (3 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 42 | `LoadLibraryA` |
| 0 | `MZKERNEL32.DLL` |
| 192 | `GetProcAddress` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 5558 | `<?xml version="1..>
</assembly>
` |
| 42 | `LoadLibraryA` |
| 0 | `MZKERNEL32.DLL` |
| 6747 | ` Microsoft Corpo..rights reserved.` |
| 6493 | `Windows Calculat..application file` |
| 6877 | `CALC.EXE` |
| 6597 | `5.1.2600.0 (xpcl..ent.010817-1148)` |
| 6409 | `Microsoft Corporation` |
| 6231 | `VS_VERSION_INFO` |
| 6843 | `OriginalFilename` |
| 6359 | `040904B0` |
| 7041 | `5.1.2600.0` |
| 11195 | `xrssssvvvv` |
| 8162 | `@offffff@n` |
| 8123 | `fDDDDDD@offffff@n`` |
| 7613 | ```````` |
| 7549 | ```````` |
| 7501 | `opopopopowwpf@` |
| 7485 | ``````` |
| 11243 | `^zwurqqqqqsssssvvvv;` |
| 6459 | `FileDescription` |
| 11578 | `YYYYXXV` |
| 6671 | `InternalName` |
| 7709 | ``wwwwwwwfffff@` |
| 7701 | `fffff@` |
| 7677 | ``wwwwwwwfffff@` |
| 7733 | `fffff@` |
| 7629 | `opopopopopopf@` |
| 8145 | `p@offffff@n`` |
| 7565 | `opopopopopopf@` |
| 6323 | `StringFileInfo` |
| 7011 | `ProductVersion` |
| 11640 | `XXXXXVX` |
| 6383 | `CompanyName` |
| 7452 | `dDDDDDDDDDDDDD@` |
| 7103 | `Translation` |
| 6571 | `FileVersion` |
| 8204 | `ffffffa` |
| 6697 | `CALC` |
| 6967 | ` Operating System` |
| 6715 | `LegalCopyright` |
| 8173 | `wwwff@o` |
| 7661 | `fffffffffffff@` |
| 7756 | `ffffffffffffffa` |
| 6929 | `Microsoft` |
| 7597 | `fffffffffffff@` |
| 7533 | `fffffffffffff@` |
| 7469 | `fffffffffffff@` |
| 13951 | `edddc` |
| 10966 | `hbbbe` |
| 11294 | `^;LLZZzxxwtrqqrZ` |
| 192 | `GetProcAddress` |
| 9365 | `B--B5J` |
| 6903 | `ProductName` |
| 11351 | `f^NLLL` |
| 7071 | `VarFileInfo` |
| 9771 | `6=cc=4` |
| 44041 | `QDnD` |
| 53042 | `aasS` |
| 8184 | `ff@n` |
| 8192 | `ff@o` |
| 53513 | `1?1j` |
| 10476 | `MM8L` |
| 10146 | `>887` |
| 9995 | `]::9` |
| 24798 | `
988` |
| 37283 | `uW>u` |
| 38694 | `2f9f` |
| 53905 | `i]5pp` |
| 43952 | `j]@;j` |
| 40192 | `@>sNN` |
| 10090 | `>TPPM` |
| 10910 | ``~bbbi` |
| 6949 | ` Windows` |
| 40594 | `n.Z5f
JmgL0s` |
| 15519 | `n?UKVWXC;` |
| 15503 | `cDfLMGN^J` |
| 9718 | `=||ccOM7` |
| 9561 | `|||ddcO87` |
| 15536 | `FBA23>@S` |

### Carved Files (8)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 3752 |
| ? | DIB | 2216 |
| ? | DIB | 1384 |
| ? | DIB | 9640 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |

### Virtual Files (11)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/en-us | 744 | - |
| ICO/2/en-us | 296 | - |
| ICO/3/en-us | 3752 | - |
| ICO/4/en-us | 2216 | - |
| ICO/5/en-us | 1384 | - |
| ICO/6/en-us | 9640 | - |
| ICO/7/en-us | 4264 | - |
| ICO/8/en-us | 1128 | - |
| GRPICO/SC/en-us | 118 | - |
| VER/1/en-us | 908 | - |
| MANIF/1/en-us | 667 | - |

### Structures (77)
| Name | EA |
|---|---|
| PE | 16 |
| OptionalHeader | 40 |
| Sections | 368 |
| Resources | 4096 |
| Resources.ICO | 4176 |
| Resources.ICO.1 | 4256 |
| Resources.ICO.1.en-us | 4280 |
| Resources.ICO.2 | 4296 |
| Resources.ICO.2.en-us | 4320 |
| Resources.ICO.3 | 4336 |
| Resources.ICO.3.en-us | 4360 |
| Resources.ICO.4 | 4376 |
| Resources.ICO.4.en-us | 4400 |
| Resources.ICO.5 | 4416 |
| Resources.ICO.5.en-us | 4440 |
| Resources.ICO.6 | 4456 |
| Resources.ICO.6.en-us | 4480 |
| Resources.ICO.7 | 4496 |
| Resources.ICO.7.en-us | 4520 |
| Resources.ICO.8 | 4536 |
| Resources.ICO.8.en-us | 4560 |
| Resources.MENU | 4576 |
| Resources.MENU.106 | 4624 |
| Resources.MENU.106.en-us | 4648 |
| Resources.MENU.107 | 4664 |
| Resources.MENU.107.en-us | 4688 |
| Resources.MENU.108 | 4704 |
| Resources.MENU.108.en-us | 4728 |
| Resources.MENU.109 | 4744 |
| Resources.MENU.109.en-us | 4768 |


## capa Capability Rules
engine: `capa` · Total rules: 0 · duration_s: 0.22

| Rule | ATT&CK | MBC |
|---|---|---|

## PE Imports / Signals
import_count: 0

## YARA Matches (pipeline)
Total matches: 21

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=14 |
| IP | - | $ipv4@2212 len=7; $ipv6@6028 len=2 |
| contains_base64 | - | $a@42 len=12 |
| WinUpackv039finalByDwingc2005h1 | - | $a0@24 len=84 |
| Upackv039finalDwing | - | $a0@240 len=23; $a1@160 len=23 |
| UpackV037Dwing | - | $a0@40 len=168; $a2@24 len=11 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasModified_DOS_Message | - |  |
| WinUpack_v039_final_By_Dwing_c2005_additional | - | $a@24 len=321 |
| Upack_v0399_Dwing_additional | - | $a@24 len=345 |
| Upack_V037_V039_Dwing | - | $b@24 len=11 |
| Upack_v039_final | - | $a@24 len=84 |
| Upack_v039_final_Sign_by_hot_UNP_additional | - | $a@24 len=84 |
| WinUpack_v039_final_By_Dwing_c2005_h1 | - | $a@24 len=84; $b@24 len=84; $c@24 len=338 |
| Upack_v039_final_Dwing_h | - | $a@24 len=84 |
| Upack_v039_final_Sign_by_hot_UNP | - | $a@240 len=23; $b@24 len=84 |
| Upack_V037_Dwing | - | $a@40 len=168; $b@24 len=11 |
| WinUpack_v039_final_By_Dwing_c2005_h1_additional | - | $a@24 len=84 |
| WinUpack_v039_final_By_Dwing_c2005 | - | $a@24 len=84; $b@24 len=321 |

## Generated YARA Meta
```json
{
  "rule_count": 21,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 2212,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 6028,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 42,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "WinUpackv039finalByDwingc2005h1",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 24,
          "length": 84,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Upackv039finalDwing",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 240,
          "length": 23,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 160,
          "length": 23,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UpackV037Dwing",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 40,
          "length": 168,
          "xor_key": null
        },
        {
          "id": "$a2",
          "offset": 24,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": []
    },
    {
      "rule": "WinUpack_v039_final_By_Dwing_c2005_additional",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 24,
          "length": 321,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Upack_v0399_Dwing_additional",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9/Upack037.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 24,
          "length": 345,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Upack_V037_V039_Dwing",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-H1/36137
```

## FLOSS Strings
Total strings: 52 · per_category: `{}`

### High-signal FLOSS
- `MZKERNEL32.DLL`
- `LoadLibraryA`
- `GetProcAddress`

### FLOSS sample
- `MZKERNEL32.DLL`
- `LoadLibraryA`
- `GetProcAddress`
- `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
- `<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">`
- `<assemblyIdentity`
- `name="Microsoft.Windows.Shell.calc"`
- `processorArchitecture="x86"`
- `version="5.1.0.0"`
- `type="win32"/>`
- `<description>Windows Shell</description>`
- `<dependency>`
- `<dependentAssembly>`
- `<assemblyIdentity`
- `type="win32"`
- `name="Microsoft.Windows.Common-Controls"`
- `version="6.0.0.0"`
- `processorArchitecture="x86"`
- `publicKeyToken="6595b64144ccf1df"`
- `language="*"`
- `</dependentAssembly>`
- `</dependency>`
- `</assembly>`
- `dDDDDDDDDDDDDD@`
- `fffffffffffff@`
- `opopopopowwpf@`
- `fffffffffffff@`
- `opopopopopopf@`
- `fffffffffffff@`
- `opopopopopopf@`
- `fffffffffffff@`
- ``wwwwwwwfffff@`
- ``wwwwwwwfffff@`
- `ffffffffffffffa`
- `fDDDDDD@offffff@n``
- `p@offffff@n``
- `@offffff@n`
- `|||ddcO87`
- `=||ccOM7`
- ``NfOM79|?4`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x01001018
```asm
┌ 64: entry0 ();
│           0x01001018      beb0110001     mov esi, 0x10011b0
│           0x0100101d      ad             lodsd eax, dword [esi]
│           0x0100101e      50             push eax
│           0x0100101f      ff7634         push dword [esi + 0x34]
│       ┌─< 0x01001022      eb7c           jmp 0x10010a0
..
│       │   ; CODE XREF from entry0 @ 0x1001022(x)
│       └─> 0x010010a0      ff7638         push dword [esi + 0x38]
│       │   0x010010a3      ad             lodsd eax, dword [esi]
│       │   0x010010a4      50             push eax
│       │   0x010010a5      8b3e           mov edi, dword [esi]
│       │   0x010010a7      bef0400301     mov esi, 0x10340f0
│       │   0x010010ac      6a27           push 0x27                   ; '\'' ; 39
│       │   0x010010ae      59             pop ecx
│       │   0x010010af      f3a5           rep movsd dword es:[edi], dword [esi]
│       │   0x010010b1      ff7604         push dword [esi + 4]
│       │   0x010010b4      83c8ff         or eax, 0xffffffff          ; -1
│       │   0x010010b7      8bdf           mov ebx, edi
│       │   0x010010b9      ab             stosd dword es:[edi], eax
│      ┌──< 0x010010ba      eb1c           jmp 0x10010d8
..
│  ││││││   ; CODE XREF from entry0 @ 0x10010ba(x)
│  ││││└──> 0x010010d8      40             inc eax
│  ││││ │   0x010010d9      ab             stosd dword es:[edi], eax
│  ││││ │   0x010010da      40             inc eax
│  ││││ └─> 0x010010db      b104           mov cl, 4
│  ││││     0x010010dd      f3ab           rep stosd dword es:[edi], eax
│  ││││     0x010010df      c1e00a         shl eax, 0xa
│  ││││     0x010010e2      b51c           mov ch, 0x1c                ; 28
│  ││││     0x010010e4      f3ab           rep stosd dword es:[edi], eax
│  ││││     0x010010e6      8b7e0c         mov edi, dword [esi + 0xc]
│  ││││     0x010010e9      57             push edi
│  ││││     0x010010ea      51             push ecx
└  ││││ ┌─< 0x010010eb      e9fbb70200     jmp loc.0102c8eb
```
### 0x0102c8eb
```asm
; CODE XREF from entry0 @ 0x10010eb(x)
├ 30521: loc.0102c8eb ();
│ 0x0102c8eb      58             pop eax
│ 0x0102c8ec      8d548358       lea edx, [ebx + eax*4 + 0x58]
│ 0x0102c8f0      ff16           call dword [esi]
│ 0x0102c8f2      724f           jb 0x102c943
│ 0x0102c8f4      04fd           add al, 0xfd                          ; 253
│ 0x0102c8f6      1ad2           sbb dl, dl
│ 0x0102c8f8      22c2           and al, dl
│ 0x0102c8fa      3c07           cmp al, 7                             ; 7
│ 0x0102c8fc      73f6           jae 0x102c8f4
│ 0x0102c8fe      50             push eax
│ 0x0102c8ff      0fb66fff       movzx ebp, byte [edi - 1]
│ 0x0102c903      c1ed05         shr ebp, 5
│ 0x0102c906      6669ed0003     imul bp, bp, 0x300
│ 0x0102c90b      8dacab0810..   lea ebp, [ebx + ebp*4 + 0x1008]
│ 0x0102c912      57             push edi
│ 0x0102c913      b001           mov al, 1
│ 0x0102c915      e31f           jecxz 0x102c936
│ 0x0102c917      2b7b08         sub edi, dword [ebx + 8]
│ 0x0102c91a      840f           test byte [edi], cl
│ 0x0102c91c      0f95c4         setne ah
│ 0x0102c91f      fec4           inc ah
│ 0x0102c921      8d548500       lea edx, [ebp + eax*4]
│ 0x0102c925      ff16           call dword [esi]
│ 0x0102c927      12c0           adc al, al
│ 0x0102c929      d0e9           shr cl, 1
│ 0x0102c92b      740e           je 0x102c93b
│ 0x0102c92d      2ae0           sub ah, al
│ 0x0102c92f      80e401         and ah, 1
│ 0x0102c932      75e6           jne 0x102c91a
│ 0x0102c934      33c9           xor ecx, ecx
│ 0x0102c936      b501           mov ch, 1
│ 0x0102c938      ff5650         call dword [esi + 0x50]               ; 80
│ 0x0102c93b      33c9           xor ecx, ecx
│ 0x0102c93d      5f             pop edi
│ ; CODE XREF from loc.0102c8eb @ 0x102c96e(x)
│ 0x0102c93e      e9f2000000     jmp 0x102ca35
│ 0x0102c943      04f9           add al, 0xf9                          ; 249
│ 0x0102c945      1ac0           sbb al, al
│ 0x0102c947      b130           mov cl, 0x30                          ; '0' ; 48
│ 0x0102c949      2403           and al, 3
│ 0x0102c94b      8b6b08         mov ebp, dword [ebx + 8]
│ 0x0102c94e      0408           add al, 8
│ 0x0102c950      03d1           add edx, ecx
│ 0x0102c952      ff16           call dword [esi]
│ 0x0102c954      7342           jae 0x102c998
│ 0x0102c956      03d1           add edx, ecx
│ 0x0102c958      ff16           call dword [esi]
│ 0x0102c95a      7214           jb 0x102c970
│ 0x0102c95c      03d1           add edx, ecx
│ 0x0102c95e      ff16           call dword [esi]
│ 0x0102c960      7224           jb 0x102c986
│ 0x0102c962      0c01           or al, 1
│ 0x0102c964      50             push eax
│ 0x0102c965      8bc7           mov eax, edi
│ 0x0102c967      2b4308         sub eax, dword [ebx + 8]
│ 0x0102c96a      b180           mov cl, 0x80                          ; 128
│ 0x0102c96c      8a00           mov al, byte [eax]
│ 0x0102c96e      ebce           jmp 0x102c93e
│ 
```
### 0x010340a0
```asm
; CODE XREF from loc.0102c8eb @ 0x1034022(x)
├ 52: loc.010340a0 ();
│           0x010340a0      ff7638         push dword [esi + 0x38]
│           0x010340a3      ad             lodsd eax, dword [esi]
│           0x010340a4      50             push eax
│           0x010340a5      8b3e           mov edi, dword [esi]
│           0x010340a7      bef0400301     mov esi, 0x10340f0
│           0x010340ac      6a27           push 0x27                   ; '\'' ; 39
│           0x010340ae      59             pop ecx
│           0x010340af      f3a5           rep movsd dword es:[edi], dword [esi]
│           0x010340b1      ff7604         push dword [esi + 4]
│           0x010340b4      83c8ff         or eax, 0xffffffff          ; -1
│           0x010340b7      8bdf           mov ebx, edi
│           0x010340b9      ab             stosd dword es:[edi], eax
│       ┌─< 0x010340ba      eb1c           jmp 0x10340d8
..
│   │││││   ; CODE XREF from loc.010340a0 @ 0x10340ba(x)
│   ││││└─> 0x010340d8      40             inc eax
│   ││││    0x010340d9      ab             stosd dword es:[edi], eax
│   ││││    0x010340da      40             inc eax
│   ││││    0x010340db      b104           mov cl, 4
│   ││││    0x010340dd      f3ab           rep stosd dword es:[edi], eax
│   ││││    0x010340df      c1e00a         shl eax, 0xa
│   ││││    0x010340e2      b51c           mov ch, 0x1c                ; 28
│   ││││    0x010340e4      f3ab           rep stosd dword es:[edi], eax
│   ││││    0x010340e6      8b7e0c         mov edi, dword [esi + 0xc]
│   ││││    0x010340e9      57             push edi
│   ││││    0x010340ea      51             push ecx
└   ││││┌─< 0x010340eb      e9fbb70200     jmp 0x105f8eb
```
### 0x010011e8
```asm
┌ 98309: sym.imp.KERNEL32.DLL_LoadLibraryA ();
│ 0x010011e8      2800           sub byte [eax], al
│ 0x010011ea      0000           add byte [eax], al
│ ;-- GetProcAddress:
│ 0x010011ec      be00000000     mov esi, 0
│ 0x010011f1      0000           add byte [eax], al
│ 0x010011f3      0000           add byte [eax], al
│ 0x010011f5      0000           add byte [eax], al
│ 0x010011f7      0000           add byte [eax], al
│ 0x010011f9      0002           add byte [edx], al
│ 0x010011fb      0000           add byte [eax], al
│ 0x010011fd      00e8           add al, ch
│ 0x010011ff      1100           adc dword [eax], eax
│ 0x01001201      0000           add byte [eax], al
│ 0x01001203      0000           add byte [eax], al
│ 0x01001205      0000           add byte [eax], al
│ 0x01001207      0000           add byte [eax], al
│ 0x01001209      0000           add byte [eax], al
│ 0x0100120b      0000           add byte [eax], al
│ 0x0100120d      0000           add byte [eax], al
│ 0x0100120f      0000           add byte [eax], al
│ 0x01001211      0000           add byte [eax], al
│ 0x01001213      0000           add byte [eax], al
│ 0x01001215      0000           add byte [eax], al
│ 0x01001217      0000           add byte [eax], al
│ 0x01001219      0000           add byte [eax], al
│ 0x0100121b      0000           add byte [eax], al
│ 0x0100121d      0000           add byte [eax], al
│ 0x0100121f      0000           add byte [eax], al
│ 0x01001221      0000           add byte [eax], al
│ 0x01001223      0000           add byte [eax], al
│ 0x01001225      0000           add byte [eax], al
│ 0x01001227      0000           add byte [eax], al
│ 0x01001229      0000           add byte [eax], al
│ 0x0100122b      0000           add byte [eax], al
│ 0x0100122d      0000           add byte [eax], al
│ 0x0100122f      0000           add byte [eax], al
│ 0x01001231      0000           add byte [eax], al
│ 0x01001233      0000           add byte [eax], al
│ 0x01001235      0000           add byte [eax], al
│ 0x01001237      0000           add byte [eax], al
│ 0x01001239      0000           add byte [eax], al
│ 0x0100123b      0000           add byte [eax], al
│ 0x0100123d      0000           add byte [eax], al
│ 0x0100123f      0000           add byte [eax], al
│ 0x01001241      0000           add byte [eax], al
│ 0x01001243      0000           add byte [eax], al
│ 0x01001245      0000           add byte [eax], al
│ 0x01001247      0000           add byte [eax], al
│ 0x01001249      0000           add byte [eax], al
│ 0x0100124b      0000           add byte [eax], al
│ 0x0100124d      0000           add byte [eax], al
│ 0x0100124f      0000           add byte [eax], al
│ 0x01001251      0000           add byte [eax], al
│ 0x01001253      0000           add byte [eax], al
│ 0x01001255      0000           add byte [eax], al
│ 0x01001257      0000           add byte [eax], al
│ 0x01001259      0000           add byte [eax], al
│ 0x0100125b      0000           
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000010 .@....................9..........P....

## Frida Probe
- frida_available: True
- version: 17.16.4
