> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 10:13:56 UTC

## 1. Executive Summary

The sample `want.exe` (SHA256: `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09`) is a malicious Windows PE executable packed with PECompact v2.x. The binary exhibits strong indicators of malicious intent, including high entropy (7.94), minimal imports focused on dynamic API resolution and memory allocation, and executable/writable sections characteristic of self-modifying unpacking stubs. VirusTotal detections (59 malicious) associate it with Lockbit ransomware. The actual payload is entirely opaque to static analysis and would only execute at runtime after unpacking. We assess with high confidence (90%) that this sample is malicious and likely associated with ransomware activity.

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09` |
| File Path | `/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe` |
| File Size | 68,096 bytes |
| File Type | PE (Portable Executable) |
| Architecture | X86 |
| Entry Point EA | 1024 |
| Entropy | 7.94 |
| File Name | `want.exe` |
| Verdict | Malicious (score: 80) |
| Family Guess | `ransomware.lockbit` |
| Agreement | `llm_and_v1_agree` |

**Source:** (source: malcat, query_or_table: file_summary, row_or_rule: all rows, why: Provides authoritative metadata for the sample including size, type, architecture, entry point, and entropy.)

## 3. File Layout & Structural Analysis

The PE file contains four sections with notable anomalies. The `.text` section has high entropy (226/256 ≈ 0.88) and RWX permissions, indicating encrypted/compressed content and self-modifying capabilities. The `.rsrc` section also has RWX permissions, which is unusual and suspicious. The large difference between physical and virtual sizes in `.text` suggests significant padding or unpacking stubs.

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 42 | - |
| .text | 1024 | 62464 | 163840 | 226 | RWX |
| .rsrc | 164864 | 4096 | 4096 | 0 | RWX |
| .reloc | 168960 | 512 | 4096 | 0 | RW |

**Source:** (source: malcat, query_or_table: File Layout, row_or_rule: all rows, why: Shows section layout with permissions and entropy, highlighting RWX sections and high entropy in .text.)

The file contains 9 structures including MZ, RichHeader, PE, OptionalHeader, Sections, kernel32.OFT, ImportTable, ImportNames, and Relocations. The RichHeader indicates Visual Studio 2017 compilation.

**Source:** (source: malcat, query_or_table: Structures, row_or_rule: all rows, why: Lists PE structures confirming standard layout with packer artifacts.)

## 4. Static Code Analysis

### 4.1 Imports & Signals

The binary imports only 4 APIs from kernel32.dll, which is the minimal set required for runtime unpacking and dynamic API resolution. This is a classic packer stub API set.

| EA | Name | Type | Refs |
|---|---|---|---|
| 164880 | kernel32.LoadLibraryA | IMPORT | 2 |
| 164884 | kernel32.GetProcAddress | IMPORT | 0 |
| 164888 | kernel32.VirtualAlloc | IMPORT | 0 |
| 164892 | kernel32.VirtualFree | IMPORT | 0 |

**Source:** (source: malcat, query_or_table: Imports, row_or_rule: all rows, why: Shows minimal imports focused on dynamic resolution and memory allocation.)

The import signal analysis maps these APIs to MITRE ATT&CK techniques:
- `LoadLibrary` → T1129 (Shared Module)
- `GetProcAddress` → T1129 (Shared Module)
- `VirtualAlloc` → T1055 (Process Injection)

**Source:** (source: pe_imports, query_or_table: imports, row_or_rule: all rows, why: Maps APIs to ATT&CK techniques indicating dynamic resolution and injection patterns.)

### 4.2 Functions

Only two functions are visible in the binary:

| EA | Name |
|---|---|
| 1024 | EntryPoint |
| 168332 | sub_429d8c |

**Source:** (source: malcat, query_or_table: Functions, row_or_rule: all rows, why: Shows minimal visible functions, confirming the entire codebase is hidden inside the packed blob.)

The entry point function at 0x401000 is 112 bytes and appears to be a packer stub. The decompilation shows it sets up an exception handler and contains obfuscated code:

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
```

**Source:** (source: radare2, query_or_table: Disassembly, row_or_rule: 0x00401000, why: Shows entry point disassembly with packer stub code including SEH setup and obfuscated instructions.)

The entry point sets up a structured exception handler (SEH) and contains obfuscated code that likely performs unpacking. The `mov eax, 0x429d8c` instruction loads the address of `sub_429d8c`, which appears to be a secondary unpacking function.

### 4.3 Strings Analysis

FLOSS extracted 148 static strings, but most appear to be random/encrypted byte sequences. Only a few meaningful strings were found:

- `!This program cannot be run in DOS mode.` (standard PE header)
- `.reloc` (section name)
- `PECompact2` (packer identifier)

**Source:** (source: floss, query_or_table: FLOSS sample, row_or_rule: all rows, why: Shows extracted strings with most being random/encrypted, confirming payload encryption.)

Malcat identified 3 high-signal strings:

| EA | String |
|---|---|
| 164940 | `kernel32.dll` |
| 164974 | `GetProcAddress` |
| 164958 | `LoadLibraryA` |

**Source:** (source: malcat, query_or_table: High-Signal Strings, row_or_rule: all rows, why: Shows the only meaningful strings related to dynamic API resolution.)

### 4.4 YARA Matches

26 YARA rules matched, with 10+ specifically identifying PECompact v2.x packing:

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

**Source:** (source: yara, query_or_table: YARA Matches, row_or_rule: all rows, why: Shows extensive YARA matches confirming PECompact packing and other suspicious characteristics.)

The `contains_base64` rule matched at offset 63582, indicating encoded payload content. The `domain` rule matched at offset 0, which may indicate C2 communication patterns.

### 4.5 Anomalies

Malcat detected 10 anomalies:

| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| MultiplePackers | 4 | packers | 1 | File is packed using multiple packers, very suspicious |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 3 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-references |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 4 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or that the code is packed |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all initialized data sections (raw or virtual) |
| Packed | 2 | packers | 1 | File is packed using a legit or less-legit obfuscator |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

**Source:** (source: malcat, query_or_table: Anomalies, row_or_rule: all rows, why: Shows multiple suspicious anomalies including packing, high entropy, and section permission issues.)

The `GuiSubsystemNoWindowApi` anomaly at EA 324 indicates a GUI PE with zero user32 window imports, which is suspicious for a legitimate application.

### 4.6 capa Analysis

capa returned empty rules, likely due to the packed nature of the binary. This is a soft failure as capa cannot analyze packed samples effectively.

**Source:** (source: capa, query_or_table: capa Capability Rules, row_or_rule: empty, why: capa returned no rules due to packing, indicating the payload is obfuscated.)

## 5. Behavioral & Dynamic Analysis

### 5.1 Speakeasy

Speakeasy recorded no API calls or events. This is expected for a packed sample that requires runtime unpacking to execute its payload.

**Source:** (source: speakeasy, query_or_table: Speakeasy (dynamic), row_or_rule: all rows, why: Shows no runtime behavior observed, consistent with packed sample requiring unpacking.)

### 5.2 Frida Probe

Frida identified hook candidates for the 4 imported APIs:
- `kernel32.dll!LoadLibraryA`
- `kernel32.dll!GetProcAddress`
- `kernel32.dll!VirtualAlloc`
- `kernel32.dll!VirtualFree`

**Source:** (source: frida_probe, query_or_table: Frida Probe, row_or_rule: hook_candidates, why: Shows APIs that would be hooked for dynamic analysis, confirming the minimal import set.)

### 5.3 UPX Unpack

UPX unpacking failed (`upx_ok: False`), confirming the sample uses a different packer (PECompact) rather than UPX.

**Source:** (source: upx, query_or_table: UPX Unpack, row_or_rule: all rows, why: Shows UPX unpacking failed, confirming PECompact packing.)

### 5.4 XOR Search

XOR search found a pattern at position 00000000: `000000E8 ........!..L.!This program cannot be r`, which is the standard PE header XORed with 0x00.

**Source:** (source: xor, query_or_table: XOR Search, row_or_rule: all rows, why: Shows XOR pattern in PE header, likely part of packer obfuscation.)

## 6. Network Indicators & C2

The `domain` YARA rule matched at offset 0, which may indicate C2 communication patterns. However, no specific domains or IPs were extracted from the sample. The high entropy and packing suggest any network indicators would be encrypted within the payload.

**Source:** (source: yara, query_or_table: YARA Matches, row_or_rule: domain rule, why: Shows potential C2 pattern match, but no specific indicators extracted.)

## 7. Capabilities Assessment

Based on the analysis, the sample likely possesses the following capabilities:

1. **Dynamic API Resolution**: Uses `LoadLibrary` and `GetProcAddress` to resolve APIs at runtime (MITRE T1129)
2. **Memory Injection**: Uses `VirtualAlloc` for memory allocation, potentially for process injection (MITRE T1055)
3. **Self-Modification**: RWX sections allow runtime code modification
4. **Anti-Analysis**: High entropy, packing, and encrypted strings evade static analysis
5. **Persistence**: Likely implements persistence mechanisms (inferred from ransomware association)

**Source:** (source: pe_imports, query_or_table: imports, row_or_rule: all rows, why: Maps APIs to capabilities based on ATT&CK techniques.)

## 8. Indicators of Compromise

### File-Based IOCs
- **SHA256**: `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09`
- **File Name**: `want.exe`
- **File Size**: 68,096 bytes
- **File Type**: PE (Portable Executable)
- **Packer**: PECompact v2.x

### Behavioral IOCs
- Minimal imports (4 APIs from kernel32.dll)
- High entropy sections (7.94 overall, 226/256 in .text)
- RWX sections (.text and .rsrc)
- GUI subsystem without window APIs
- Unreferenced imports

### YARA Rules
- `PECompactV2XBitsumTechnologies`
- `PECompact2xxBitSumTechnologies`
- `PECompactv2xx`
- `pecompact2`
- `contains_base64`
- `domain`

**Source:** (source: malcat, query_or_table: file_summary, row_or_rule: all rows, why: Provides file-based IOCs.)
**Source:** (source: yara, query_or_table: YARA Matches, row_or_rule: all rows, why: Provides YARA rule IOCs.)

## 9. Detection Engineering

### YARA Rules
```yara
rule PECompact_Packed_Malware {
    meta:
        description = "Detects PECompact packed malware with suspicious characteristics"
        author = "Malware Analyst"
        date = "2024"
        hash = "d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09"
    strings:
        $pecompact = "PECompact2" ascii
        $kernel32 = "kernel32.dll" ascii
        $loadlibrary = "LoadLibraryA" ascii
        $getprocaddress = "GetProcAddress" ascii
        $virtualalloc = "VirtualAlloc" ascii
        $virtualfree = "VirtualFree" ascii
    condition:
        uint16(0) == 0x5A4D and
        $pecompact and
        $kernel32 and
        $loadlibrary and
        $getprocaddress and
        $virtualalloc and
        $virtualfree and
        filesize < 100KB
}
```

### Sigma Rules
```yaml
title: PECompact Packed Malware Execution
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects execution of PECompact packed malware with minimal imports
author: Malware Analyst
date: 2024/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\want.exe'
    condition: selection
falsepositives:
    - Legitimate software packed with PECompact
level: high
```

### Behavioral Detections
- Monitor for processes with minimal imports (4-5 APIs from kernel32.dll)
- Detect RWX section allocations in memory
- Watch for dynamic API resolution patterns (LoadLibrary + GetProcAddress sequences)
- Alert on high entropy memory regions (>7.5)

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Defense Evasion | Obfuscated Files or Information | T1027 | PECompact packing, high entropy, encrypted strings |
| Defense Evasion | Process Injection | T1055 | VirtualAlloc import for memory allocation |
| Execution | Shared Modules | T1129 | LoadLibrary and GetProcAddress for dynamic API resolution |
| Discovery | System Information Discovery | T1082 | Likely payload capability (inferred from ransomware association) |
| Impact | Data Encrypted for Impact | T1486 | Ransomware association (Lockbit) |

**Source:** (source: pe_imports, query_or_table: imports, row_or_rule: all rows, why: Maps APIs to ATT&CK techniques.)
**Source:** (source: External TI, query_or_table: VirusTotal, row_or_rule: ransomware.lockbit, why: Provides ransomware association for impact tactic.)

## 11. What We Don't Know

1. **Actual Payload**: The packed payload is entirely opaque to static analysis. We cannot determine its exact functionality without runtime unpacking.
2. **C2 Infrastructure**: No specific C2 domains or IPs were extracted. The `domain` YARA match may be a false positive or encrypted within the payload.
3. **Persistence Mechanisms**: While likely present (ransomware association), specific persistence methods are unknown.
4. **Encryption Algorithms**: The encryption methods used for strings and payload are unknown.
5. **Lateral Movement**: Whether the sample includes lateral movement capabilities is unknown.
6. **Data Exfiltration**: Whether data exfiltration occurs before encryption is unknown.
7. **Anti-Analysis Techniques**: Specific anti-debug or anti-VM techniques beyond packing are unknown.
8. **Configuration**: C2 URLs, encryption keys, and other configuration data are encrypted.

## 12. Appendix A: Tool Evidence Trail

### Tool Execution Summary
| Tool | Status | Notes |
|---|---|---|
| capa | Soft fail | Empty rules due to packing |
| yara | Success | 26 matches |
| floss | Success | 148 strings extracted |
| pe_imports | Success | 4 imports analyzed |
| malcat | Success | Full analysis with anomalies |
| radare2 | Success | Disassembly of entry point |
| upx | Success | Failed to unpack (not UPX) |
| xor | Success | Found XOR pattern |
| speakeasy | Success | No runtime behavior observed |
| frida_probe | Success | Hook candidates identified |

### Evidence Citations
- **Malcat**: File summary, layout, anomalies, strings, imports, functions, structures
- **YARA**: 26 rule matches including PECompact and domain rules
- **FLOSS**: 148 static strings extracted
- **PE Imports**: 4 imports with ATT&CK mapping
- **Radare2**: Entry point disassembly
- **External TI**: VirusTotal with 59 malicious detections

## 13. Appendix B: Analysis Environment

- **Analysis Date**: 2024
- **Analyst**: Automated Malware Analysis Pipeline
- **Tools Used**: capa, yara, floss, pe_imports, malcat, radare2, upx, xor, speakeasy, frida_probe
- **Environment**: Isolated malware analysis sandbox
- **Sample Source**: `/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe`
- **Project**: malware
## Appendix: Full Structured Evidence Pack

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
