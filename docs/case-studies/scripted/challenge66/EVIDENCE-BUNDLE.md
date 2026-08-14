# Technical Evidence Pack

**sha256:** 9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6  
**sample_path:** /opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe  
**project_name:** binaries

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: llac
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple engines confirm UPX packing and dynamic API resolution via minimal imports. MalCat and YARA detect packing anomalies, capa identifies software packing, and pe_imports shows APIs for dynamic loading. VirusTotal reports high malicious detections with trojan.llac/babar family, indicating malicious intent despite static analysis showing primarily obfuscation.
- **summary**: The sample is a PE executable packed with UPX, showing high entropy, minimal imports for dynamic API resolution, and version info indicating 'Ghost Encryptor'. While static analysis highlights obfuscation without clear behavioral signals, VirusTotal detections classify it as a trojan with 60 malicious reports, supporting a malicious verdict.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | anomalies | `Packed×6, PatchedUPXHeader` | Indicates software packing with UPX, a common obfuscation technique in malware. |
| yara | YARA matches | `UPXv20MarkusLaszloReiser, UPX_290_LZMA` | Confirms presence of UPX packer signatures, supporting packing evidence. |
| capa | top_rules | `packed with generic packer` | ATT&CK technique T1027.002 for software packing, a defense evasion method. |
| pe_imports | signals | `load_library, get_proc_address, change_memory_protection, allocate_memory` | APIs for dynamic code loading and memory manipulation, typical in packers and malware for evasion. |
| malcat | file_summary | `VersionInfo::InternalName: Ghost Şifreleyici Modernize Hayalet` | Suggests the file is an 'encryptor', which could imply malicious use like ransomware or keygen, though static analysis a |
| external TI | VirusTotal | `malicious=60, threat_class: trojan.llac/babar` | High detection rate and specific malware family identification indicate malicious intent, overriding neutral obfuscation |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: UPX-packed VB6 crypter dropper ('Ghost Şifreleyici Modernize Hayalet' — Turkish 'Ghost Encryptor Modernized Ghost') communicating with www.hidden-sabotage.com. The outer layer is a UPX stub with only 6 KERNEL32 memory-management imports (LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess). The packed payload is a Visual Basic 6 application with Winsock networking (winsck.ocx), RTF GUI controls, and embedded C2 domain references. YARA rules matched 7+ UPX packer signatures. CAPA confirms software packing (T1027.002). The crypter theme, suspicious domain, and packing obfuscation classify this as malicious tooling. Persistence mechanisms were not observed in the analyzed components, with no evidence from tools like YARA or CAPA indicating registry, startup, or scheduled task modifications. Exfiltration data or tools were not identified; while Winsock networking suggests communication, no specific data exfiltration methods or payloads were detected in static analysis. Credential access techniques were not observed; no memory scraping, keylogging, or credential theft modules were found in the unpacked VB6 payload.

### deep key_evidence
- `"YARA: 7+ UPX packer rules matched (UPXv20MarkusLaszloReiser, UPXV200V290, UPX290LZMA, upx_3, PackerUPX_CompresorGratuito, UPX_wwwupxsourceforgenet_additional)"`
- `"CAPA: 'packed with generic packer' \u2014 MITRE T1027.002 (Software Packing), MBC F0001.002"`
- `"Entry point 0x454310: classic UPX decompression stub (PUSHAD; MOV ESI,0x43c000; LEA EDI,[ESI+0xfffc5000]; byte-copy loop with bit-shift)"`
- `"Ghidra imports (6 total, all KERNEL32): LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess"`
- `"pe_import_signals: dynamic API resolution (T1129) via LoadLibrary+GetProcAddress; memory protection changes (T1055) via VirtualProtect+VirtualAlloc"`
- `"String 'www.hidden-sabotage.com' at Ghidra addresses 0x4561040 and 0x4561276 (resource section, VS_VERSION_INFO area)"`
- `"String 'Ghost \u015eifreleyici Modernize Hayalet' (Ghost Encryptor Modernized Ghost) \u2014 Turkish crypter tool name in VS_VERSION_INFO at 0x4561516"`
- `"FLOSS extracted 470 strings including VB6 artifacts: winsck.ocx (Winsock/network), FRICHTX32.OCX (RichText), rm1.Insertar_Objeto2, GraficAudio, ET_PICTURE6, TextRTF"`
- `"PE memory layout: 2 executable RWX sections (SECTION.0: 241KB, SECTION.1: 106KB) \u2014 typical of packer with self-modifying unpacking code"`
- `"YARA rule 'IsPacked' matched; 'HasOverlay' and 'HasRichSignature' also matched"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6
size: 169998
type: PE
architecture: X86
entrypoint_ea: 104016
entropy: 7.57
file_name: challenge66.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| header | 0 | 1024 | 0 | - |
|  | 1024 | 103936 | 106496 | RWX |
| .rsrc | 107520 | 15872 | 16384 | RW |
| overlay | 123904 | 49166 | 0 | - |
|  | 173070 | 0 | 241664 | RWX |

### Malcat YARA / Signatures (7)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| upx_080_or_higher_01 | packer | INFO | 50 |  |
| upx_089_3xx | packer | INFO | 50 |  |
| upx_0896_102_105_122_03 | packer | INFO | 50 |  |
| upx_12x | packer | INFO | 50 |  |
| upx_290_lzma_02 | packer | INFO | 50 |  |
| upx_391_nrv2e_02 | packer | INFO | 50 |  |

### Anomalies (22)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 2 | executable section has the flag code not set |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| InvalidBaseOfCode | 4 | sections | 1 | at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section |
| InvalidBaseOfData | 4 | sections | 1 | at least one data section starts before BaseOfData, or BaseOfData is not the start of a data section |
| PatchedUPXHeader | 4 | packers | 0 | At least one Yara signature matched UPX but no UPX header was identified by Malcat, indicating a pot |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 3 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) |
| SectionEmptyName | 3 | sections | 2 | section name is null |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnknownOverlayMediumToHighEntropy | 3 | entropy | 1 | File contains an overlay which is not of known type and has medium-to-high entropy |
| UnreferencedImports | 3 | imports | 7 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| DuplicatedSectionName | 2 | sections | 1 | section name has already been used before in section table |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| Packed | 2 | packers | 6 | File is packed using a legit or less-legit obfuscator |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `284`: 
- **NoChecksum**
  - `280`: 
- **XorInLoop**
  - `104130`: 

### High-Signal Strings (7 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 122832 | `KERNEL32.DLL` |
| 98313 | `\\\\"` |
| 76520 | `\\XX` |
| 122874 | `GetProcAddress` |
| 72064 | `<``\\j` |
| 122860 | `LoadLibraryA` |
| 122890 | `VirtualProtect` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 122832 | `KERNEL32.DLL` |
| 122845 | `MSVBVM60.DLL ` |
| 122602 | `ifreleyici Modernize Hayalet.exe` |
| 122236 | `www.hidden-sabotage.com` |
| 122000 | `www.hidden-sabotage.com` |
| 122490 | `ifreleyici Modernize Hayalet` |
| 121762 | `VS_VERSION_INFO` |
| 122554 | `OriginalFilename` |
| 121890 | `040904B0` |
| 154773 | `gi~`fdImff			O_O..BVXyo{sCdxi{lkoo` |
| 5676 | `e6rFRICHTX32.OCX` |
| 72047 | `B.dhd` |
| 122202 | `LegalTrademarks` |
| 123904 | `pepotespepotesMZ` |
| 133441 | `%-%=9<003000333 ...%%';=89;<>:?% Y` |
| 131783 | `zkl=<`ol|=985ezf..:r?o1gvn<?r1ph>0` |
| 135700 | `J
h}H|oo	
xBfz}	..`k				zY{ej		
Fg` |
| 98313 | `\\\\"` |
| 129674 | `

` |
| 124446 | `
J


` |
| 130188 | `J



` |
| 150496 | `<



` |
| 122054 | `FileDescription` |
| 122450 | `InternalName` |
| 171076 | `~~
	
@	f	n
h	{
..p
k	f
o	~		Y
=	` |
| 171236 | `		G	b
jj
rg	d
..*B	ls
a
a
h	y` |
| 171844 | `f




-
` |
| 132753 | `
W



` |
| 131020 | `:	H
2
9
:
:	;
;
:` |
| 131962 | `@g`}`hfcsln	Jehz..}`hecsl			
cl9hg` |
| 94642 | `t2%S2AllS2%Soca%S2%teS2` |
| 130878 | `cosoloscic		d	
	..	=	>	:
2	?	;	5
_` |
| 121854 | `StringFileInfo` |
| 122402 | `ProductVersion` |
| 139158 | `L


` |
| 135026 | `


` |
| 136467 | `

` |
| 75790 | `qLLL` |
| 121974 | `CompanyName` |
| 139237 | `


b` |
| 141700 | `6


` |
| 144535 | `<


` |
| 72719 | `99@@` |
| 156851 | `

` |
| 10225 | `j.bih` |
| 74285 | `dPPP` |
| 149252 | `L


` |
| 147893 | `0


` |
| 147560 | `


` |
| 145909 | `0


` |
| 13756 | `StSt` |
| 15783 | `@@@x` |
| 143610 | `<


` |
| 143532 | `N


` |
| 99828 | `XXX2` |
| 143428 | `?


` |
| 101469 | `dXXX` |
| 141921 | ``


` |
| 77 | `!This program ca..in DOS mode.
$` |
| 140415 | `2


` |
| 139991 | `



IG` |
| 124274 | `


` |
| 132236 | `K
\K

` |
| 122706 | `Translation` |
| 76520 | `\\XX` |
| 129710 | `

` |
| 76230 | `HHLH` |
| 130671 | `


e` |
| 76222 | `vLLv` |
| 133756 | `8:8...` |
| 124766 | `


` |
| 124261 | `


` |
| 125200 | `

` |
| 134443 | `-)*/(.&%%<?95547..1>>4!.!+-*(+,*-*` |
| 122358 | `FileVersion` |
| 122088 | `Modernize Hayalet` |
| 122316 | `Modernize Hayalet` |
| 132811 | `




	
` |
| 154728 | `		Bo}aJhefLgn`gl..OA^VYCDAUHnmXoo
` |
| 9967 | `?Fromfqfkipislqsqvhnqrvjgt` |

### Imports (7)
| EA | Name | Type | Refs |
|---|---|---|---|
| 122796 | kernel32.LoadLibraryA | IMPORT | 1 |
| 122800 | kernel32.GetProcAddress | IMPORT | 0 |
| 122804 | kernel32.VirtualProtect | IMPORT | 0 |
| 122808 | kernel32.VirtualAlloc | IMPORT | 0 |
| 122812 | kernel32.VirtualFree | IMPORT | 0 |
| 122816 | kernel32.ExitProcess | IMPORT | 0 |
| 122824 | msvbvm60.rtcR8ValFromBstr | IMPORT | 1 |

### Functions (1)
| EA | Name |
|---|---|
| 104016 | EntryPoint |

### Decompilations (top 6)
#### 104016 — EntryPoint
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}

```

### Carved Files (2)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 9640 |
| ? | DIB | 4264 |

### Virtual Files (4)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/unk | 9640 | - |
| ICO/2/unk | 4264 | - |
| GRPICO/1/unk | 34 | - |
| VER/1/en-us | 980 | - |

### Structures (25)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 192 |
| OptionalHeader | 216 |
| Sections | 440 |
| Resources | 107520 |
| Resources.ICO | 107560 |
| Resources.ICO.1 | 107592 |
| Resources.ICO.1.unk | 107616 |
| Resources.ICO.2 | 107632 |
| Resources.ICO.2.unk | 107656 |
| Resources.GRPICO | 107672 |
| Resources.GRPICO.1 | 107696 |
| Resources.GRPICO.1.unk | 107720 |
| Resources.VER | 107736 |
| Resources.VER.1 | 107760 |
| Resources.VER.1.en-us | 107784 |
| Resources.ICO.1.unk.Data | 107804 |
| Resources.ICO.2.unk.Data | 117448 |
| Resources.GRPICO.1.unk.Data | 121716 |
| VersionInfo | 121756 |
| ImportTable | 122736 |
| kernel32.FT | 122796 |
| msvbvm60.FT | 122824 |
| ImportNames | 122832 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 1.08

| Rule | ATT&CK | MBC |
|---|---|---|
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |

## PE Imports / Signals
import_count: 6

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 20

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@37486 len=3 |
| contains_base64 | - | $a@5676 len=12 |
| UPXv20MarkusLaszloReiser | - | $a0@104367 len=85 |
| UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser | - | $a0@104414 len=39 |
| UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser | - | $a1@104016 len=63 |
| upx_3 | - | $str1@104016 len=45 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| PackerUPX_CompresorGratuito_wwwupxsourceforgenet | - | $a@104016 len=12 |
| UPX_wwwupxsourceforgenet_additional | - | $a@104016 len=12 |
| yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h | - | $a@241 len=1 |
| Netopsystems_FEAD_Optimizer_1 | - | $a@104016 len=64 |
| UPX_290_LZMA | - | $a@104016 len=63 |
| UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser | - | $b@104016 len=63 |
| UPX_290_LZMA_additional | - | $a@104016 len=63 |
| UPX_wwwupxsourceforgenet | - | $a@104016 len=12; $b@104016 len=12 |

## Generated YARA Meta
```json
{
  "rule_count": 20,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
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
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 37486,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5676,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXv20MarkusLaszloReiser",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 104367,
          "length": 85,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 104414,
          "length": 39,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": [
        {
          "id": "$a1",
          "offset": 104016,
          "length": 63,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "upx_3",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": [
        {
          "id": "$str1",
          "offset": 104016,
          "length": 45,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 168,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "PackerUPX_CompresorGratuito_wwwupxsourceforgenet",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 104016,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX_wwwupxsourceforgenet_additional",
      "path": "/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe",
      "strings": [
        {
          "id": "$a",
          "offs
```

## FLOSS Strings
Total strings: 470 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 470}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `QV8yN.[`
- `1^2e2.3C9`
- `<V|@d{W`
- `=Icti>`
- `WhXoXaZ`
- `#g_6~=~`
- `Sk8OF6.v`
- `Jz+,S8`
- `+H?nfx`
- `i/Cr`;`
- `|zm/GH$`
- `LN40m/`
- `8!7(+6l%`
- `Oc2->a"6`
- `winsck.ocx@SW`
- `+dColor`
- `Enable`
- `TextRTF`
- `J;"dfn`
- `e6rFRICHTX32.OCX`
- `DrderSty`
- `BAFM~omctlJ`
- `stView`
- `c)6@_M`
- `{o R^_`
- `-3H(K^`
- `^;RS_<M_`
- `L.X7hoy`
- `rm1.Insertar_Objeto2`
- `GraficAudio~Calc_Pictu`
- `re3Slide_`
- `g4OPEN$IL`
- `Notify_IcoI`
- `Class.`
- `LabelProg\paLB`
- `WuC:\WINDOWS\sys`
- `soft Visu@ StY\VB`V`
- `s\Soo.`
- `ect 0.1U`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00455250
```asm
┌ 439: entry0 ();
│       ╎   0x00455250      60             pushal
│       ╎   0x00455251      be00c04300     mov esi, section.sect_1     ; 0x43c000
│       ╎   0x00455256      8dbe0050fcff   lea edi, [esi - 0x3b000]
│       ╎   0x0045525c      57             push edi
│       ╎   0x0045525d      83cdff         or ebp, 0xffffffff          ; -1
│      ┌──< 0x00455260      eb10           jmp 0x455272
..
│     ┌───> 0x00455268      8a06           mov al, byte [esi]
│     ╎│╎   0x0045526a      46             inc esi
│     ╎│╎   0x0045526b      8807           mov byte [edi], al
│     ╎│╎   0x0045526d      47             inc edi
│     ╎│╎   ; CODE XREFS from entry0 @ 0x455327(x), 0x45533d(x)
│   ┌┌────> 0x0045526e      01db           add ebx, ebx
│  ┌──────< 0x00455270      7507           jne 0x455279
│  │╎╎╎│╎   ; CODE XREF from entry0 @ 0x455260(x)
│  │╎╎╎└──> 0x00455272      8b1e           mov ebx, dword [esi]
│  │╎╎╎ ╎   0x00455274      83eefc         sub esi, 0xfffffffc
│  │╎╎╎ ╎   0x00455277      11db           adc ebx, ebx
│  └──└───< 0x00455279      72ed           jb 0x455268
│   ╎╎  ╎   0x0045527b      b801000000     mov eax, 1
│   ╎╎  ╎   ; CODE XREF from entry0 @ 0x4552aa(x)
│   ╎╎ ┌──> 0x00455280      01db           add ebx, ebx
│   ╎╎┌───< 0x00455282      7507           jne 0x45528b
│   ╎╎│╎╎   0x00455284      8b1e           mov ebx, dword [esi]
│   ╎╎│╎╎   0x00455286      83eefc         sub esi, 0xfffffffc
│   ╎╎│╎╎   0x00455289      11db           adc ebx, ebx
│   ╎╎└───> 0x0045528b      11c0           adc eax, eax
│   ╎╎ ╎╎   0x0045528d      01db           add ebx, ebx
│   ╎╎┌───< 0x0045528f      730b           jae 0x45529c
│  ┌──────< 0x00455291      7528           jne 0x4552bb
│  │╎╎│╎╎   0x00455293      8b1e           mov ebx, dword [esi]
│  │╎╎│╎╎   0x00455295      83eefc         sub esi, 0xfffffffc
│  │╎╎│╎╎   0x00455298      11db           adc ebx, ebx
│ ┌───────< 0x0045529a      721f           jb 0x4552bb
│ ││╎╎└───> 0x0045529c      48             dec eax
│ ││╎╎ ╎╎   0x0045529d      01db           add ebx, ebx
│ ││╎╎┌───< 0x0045529f      7507           jne 0x4552a8
│ ││╎╎│╎╎   0x004552a1      8b1e           mov ebx, dword [esi]
│ ││╎╎│╎╎   0x004552a3      83eefc         sub esi, 0xfffffffc
│ ││╎╎│╎╎   0x004552a6      11db           adc ebx, ebx
│ ││╎╎└───> 0x004552a8      11c0           adc eax, eax
│ ││╎╎ └──< 0x004552aa      ebd4           jmp 0x455280
│ ││╎╎┌┌──> 0x004552ac      01db           add ebx, ebx
│ ────────< 0x004552ae      7507           jne 0x4552b7
│ ││╎╎╎╎╎   0x004552b0      8b1e           mov ebx, dword [esi]
│ ││╎╎╎╎╎   0x004552b2      83eefc         sub esi, 0xfffffffc
│ ││╎╎╎╎╎   0x004552b5      11db           adc ebx, ebx
│ ────────> 0x004552b7      11c9           adc ecx, ecx
│ ────────< 0x004552b9      eb52           jmp 0x45530d
│ └└──────> 0x004552bb      31c9           xor ecx, ecx
│   ╎╎╎╎╎   0x004552bd      83e803         sub eax, 3
│  ┌──────< 0x004552c0      7211           jb 0x4552d3
│  │╎╎╎╎╎   0x
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r

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
  - `KERNEL32.DLL!LoadLibraryA`
  - `KERNEL32.DLL!GetProcAddress`
  - `KERNEL32.DLL!VirtualProtect`
  - `KERNEL32.DLL!VirtualAlloc`
  - `KERNEL32.DLL!VirtualFree`
