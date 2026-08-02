## 1. Executive Summary
This sample is confirmed malicious, packed with the commercial Themida packer (ATT&CK T1027.002) to obfuscate a hidden malicious payload, with integrated anti-analysis capabilities (source: llm_judge verdict). The sample received a threat score of 88, with the underlying payload likely belonging to a common commodity malware family (trojan, info-stealer, or ransomware) that cannot be definitively identified without dynamic unpacking (source: llm_judge family_guess). Static analysis from capa, FLOSS, Ghidra, and pe_imports consistently confirms Themida packing, aPLib decompression logic, and minimal obfuscated stub code, with no high-signal malicious imports visible in the static view (source: llm_judge cross_engine_notes). IDA, YARA, and Malcat analysis were unavailable due to missing tooling, but available evidence is sufficient to classify the sample as malicious packed malware (source: llm_judge summary).

## 2. Sample Metadata
| Field | Value |
|-------|-------|
| SHA256 | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 |
| Sample Path | /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir |
| Project Name | incoming |
| Verdict | Malicious, packed with Themida (ATT&CK T1027.002) to obfuscate a hidden malicious payload, with anti-analysis capabilities |
| Threat Score | 88 |
| Family Guess | Themida-packed malicious payload (likely common commodity malware such as a trojan, info-stealer, or ransomware; exact family cannot be determined without dynamic unpacking) |
| Tool Availability Notes | IDA analysis was fully unavailable due to a missing idasql binary, YARA scanning failed due to a missing yr binary, and Malcat deep profiling failed due to a missing malcat.mcp.py script. Ghidra imports virtual table returned 0 rows, but DLL imports were identified via Ghidra's string list and corroborated by pe_imports' 3 import count (source: llm_judge cross_engine_notes). |

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows PE file with a heavily modified structure consistent with Themida packing. The most prominent structural feature is a 4.7 MB `.themida` memory section located at virtual address 0x268783616 with read/write/execute permissions (perm=7) that contains no readable static strings, indicating it holds encrypted/compressed original payload code (source: deep_dive_agentic key_evidence). The import table is severely minimized, with only 3 total imports and 0 high-signal malicious APIs, a common trait of packed binaries that strip unnecessary imports to avoid detection (source: pe_imports import_count, signal_count). The sample has a forwarded export named `InitializeSecurity`, which is a common obfuscation technique used by packers to hide malicious functionality (source: deep_dive_agentic key_evidence). Static analysis via Ghidra identified only 25 total functions and 54 visible strings, an extremely low count consistent with a small packer stub where the majority of the original payload code and strings are encrypted (source: ghidra funcs, strings count). The entry point (EP) is located at 0x104d3058, is 336 bytes in size, has 52 basic blocks, and a cyclomatic complexity of 27, indicating highly complex obfuscated code consistent with a Themida virtual machine (VM) stub (source: deep_dive_agentic key_evidence).

## 4. Malcat Triage Summary
Malcat deep profiling was unavailable for this sample due to a missing execution script: the analysis returned the error `MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory` (source: Malcat Structured Analysis). No Malcat-specific triage data, string analysis, or structural profiling could be collected from this engine.

## 5. Static Code Analysis
### Entry Point (EP) Disassembly (0x104d3058, radare2)
The EP is a classic aPLib decompression stub, consistent with capa's detection of aPLib decompression logic (source: capa top_rules "decompress data using aPLib" rule (MBC C0025.003)). The disassembly is as follows:
```asm
┌ 336: entry0 ();
│           0x104d3058      e84b010000     call 0x104d31a8
│           0x104d305d      53             push ebx
│           0x104d305e      89e3           mov ebx, esp
│           0x104d3060      53             push ebx
│           0x104d3061      8b7308         mov esi, dword [ebx + 8]
│           0x104d3064      8b7b10         mov edi, dword [ebx + 0x10]
│           0x104d3067      fc             cld
│           0x104d3068      b280           mov dl, 0x80                ; 128
│       ┌─> 0x104d306a      8a06           mov al, byte [esi]
│       ╎   0x104d306c      46             inc esi
│       ╎   0x104d306d      8807           mov byte [edi], al
│       ╎   0x104d306f      47             inc edi
│       ╎   0x104d3070      bb02000000     mov ebx, 2
│       ╎   ; CODE XREFS from entry0 @ 0x104d30da(x), 0x104d3123(x), 0x104d3163(x), 0x104d3178(x), 0x104d3199(x)
│  ┌┌┌┌┌──> 0x104d3075      00d2           add dl, dl
│ ┌───────< 0x104d3077      7505           jne 0x104d307e
│ │╎╎╎╎╎╎   0x104d3079      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎╎   0x104d307b      46             inc esi
│ │╎╎╎╎╎╎   0x104d307c      10d2           adc dl, dl
│ └─────└─< 0x104d307e      73ea           jae 0x104d306a
│  ╎╎╎╎╎    0x104d3080      00d2           add dl, dl
│  ╎╎╎╎╎┌─< 0x104d3082      7505           jne 0x104d3089
│  ╎╎╎╎╎│   0x104d3084      8a16           mov dl, byte [esi]
│  ╎╎╎╎╎│   0x104d3086      46             inc esi
│  ╎╎╎╎╎│   0x104d3087      10d2           adc dl, dl
│ ┌─────└─> 0x104d3089      7351           jae 0x104d30dc
│ │╎╎╎╎╎    0x104d308b      31c0           xor eax, eax
│ │╎╎╎╎╎    0x104d308d      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d308f      7505           jne 0x104d3096
│ │╎╎╎╎╎│   0x104d3091      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d3093      46             inc esi
│ │╎╎╎╎╎│   0x104d3094      10d2           adc dl, dl
│ ──────└─> 0x104d3096      0f83e1000000   jae 0x104d317d
│ │╎╎╎╎╎    0x104d309c      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d309e      7505           jne 0x104d30a5
│ │╎╎╎╎╎│   0x104d30a0      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30a2      46             inc esi
│ │╎╎╎╎╎│   0x104d30a3      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30a5      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30a7      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30a9      7505           jne 0x104d30b0
│ │╎╎╎╎╎│   0x104d30ab      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30ad      46             inc esi
│ │╎╎╎╎╎│   0x104d30ae      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30b0      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30b2      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30b4      7505           jne 0x104d30bb
│ │╎╎╎╎╎│   0x104d30b6      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30b8      46             inc esi
│ │╎╎╎╎╎│   0x104d30b9      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30bb      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30bd      00d2   
```
This code implements the aPLib decompression algorithm, which is used by Themida to decompress the original malicious payload at runtime (source: capa top_rules "decompress data using aPLib" rule (MBC C0025.003)).

A second obfuscated function was identified at 0x10019110, labeled `sym.StringLoaderA.dll_InitializeSecurity`, which implements the forwarded `InitializeSecurity` export. This function is heavily obfuscated with invalid instructions, opaque predicates, and VM-like code patterns consistent with Themida's anti-reversing protections (source: radare2 disassembly 0x10019110, deep_dive_agentic key_evidence).

### Full Import Address Table (IAT)
The sample has a minimized IAT with only 3 imports, all from core Windows DLLs, with no high-signal malicious APIs (source: pe_imports import_count=3, signal_count=0; ghidra Suspicious strings):
| DLL | Imported Function |
|-----|-------------------|
| KERNEL32.DLL | GetModuleHandleA |
| USER32.DLL | TranslateMessage |
| ADVAPI32.DLL | OpenProcessToken |

### High-Signal Strings (FLOSS)
FLOSS extracted 5014 total static strings from the sample, all high-entropy obfuscated except for standard PE metadata and the Themida section marker (source: floss strings). Key high-signal strings include:
- `.themida` (section marker, confirms Themida packing, source: floss strings)
- `!This program cannot be run in DOS mode.` (standard PE header string, source: floss strings)
- High-entropy obfuscated strings (e.g., `'1~`nV9F`, `\nxswz9C`, `oh.n~L`) consistent with encrypted payload data (source: floss strings)
- Strings referencing reverse engineering and analysis tools, matching capa's "reference analysis tools strings" rule (MBC B0013.001) (source: capa top_rules, floss strings)

### capa Capability Rules
capa identified 6 total rules for the sample, confirming packing and anti-analysis behavior (source: capa top_rules):
| Rule | ATT&CK | MBC |
|------|--------|-----|
| packed with Themida | T1027.002:Obfuscated Files or Information | F0001.011:Software Packing |
| decompress data using aPLib |  | C0025.003:Decompress Data |
| forwarded export | T1129:Shared Modules |  |
| reference analysis tools strings |  | B0013.001:Analysis Tool Discovery |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

### YARA Analysis
YARA scanning failed entirely due to a missing `yr` binary, with batch errors returned for all YARA rule batches (source: Generated YARA Meta). No YARA matches were collected.
```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ]
}
```

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed for this sample. Speakeasy dynamic analysis completed successfully but recorded 0 API calls and 0 key events, indicating the Themida stub did not execute any detectable behavior in the sandbox environment (source: speakeasy speakeasy_ok=True, api_calls=0, key_events=0). Frida probe version 17.16.4 was available but no runtime instrumentation data was captured (source: frida_available=True, version=17.16.4). UPX unpacking failed, as the sample is not packed with UPX, and no unpacked payload path was generated (source: upx upx_ok=False, is_packed=False, returncode=None, unpacked_path=``). No dynamic unpacking of the Themida payload was performed, so no runtime behavior of the underlying malicious payload could be observed.

## 7. Network Indicators & C2
No network indicators or C2 infrastructure were identified for this sample. No network traffic was captured during dynamic analysis (as no dynamic behavior was observed), and no C2-related strings or indicators are present in the static analysis data (source: all available evidence sources). Network IOCs will only be available after successful dynamic unpacking and execution of the underlying payload.

## 8. Capabilities & MITRE ATT&CK Mapping
Only the capabilities of the Themida packer stub could be confirmed via static analysis, as the underlying payload is obfuscated and was not unpacked. Confirmed capabilities and MITRE ATT&CK/MBC mappings are as follows (source: capa top_rules):
| Capability | ATT&CK Technique | MBC Behavior |
|------------|------------------|-------------|
| Software packing with Themida | T1027.002: Obfuscated Files or Information | F0001.011: Software Packing |
| Decompression of payload data via aPLib |  | C0025.003: Decompress Data |
| Export of forwarded shared module `InitializeSecurity` | T1129: Shared Modules |  |
| Detection of reverse engineering/analysis tools via embedded strings |  | B0013.001: Analysis Tool Discovery |
| Obfuscated loop-based control flow (packer stub) |  |  |

The underlying payload's capabilities (e.g., credential theft, ransomware encryption, C2 communication) are unknown and cannot be mapped without dynamic unpacking.

## 9. Indicators of Compromise
### Static IOCs
| IOC Type | Value | Source |
|----------|-------|--------|
| File SHA256 | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 | Structured Evidence |
| File Path | /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir | Structured Evidence |
| Section Name | `.themida` | floss strings, deep_dive_agentic |
| Forwarded Export | `InitializeSecurity` | deep_dive_agentic key_evidence, radare2 disassembly 0x10019110 |
| Minimized Import Set | GetModuleHandleA (KERNEL32.DLL), TranslateMessage (USER32.DLL), OpenProcessToken (ADVAPI32.DLL) | pe_imports, ghidra Suspicious strings |
| High-Entropy Obfuscated Strings | `'1~`nV9F`, `\nxswz9C`, `oh.n~L` (full list in FLOSS output) | floss strings |

No network C2 IOCs are available at this time, as the underlying payload is not unpacked.

## 10. Detection Engineering
YARA rule generation was not possible due to the missing `yr` binary, so no pre-existing YARA matches are available (source: Generated YARA Meta). Detection logic can be built using the following confirmed static characteristics of the sample:
1. **Packer Stub Detection**: Flag PEs with a `.themida` section, entry point with >50 basic blocks and cyclomatic complexity >25, and aPLib decompression stub signatures (source: ghidra func metrics, capa rules, radare2 EP disassembly).
2. **Import Table Detection**: Flag PEs with only 3 imports from KERNEL32.DLL, USER32.DLL, and ADVAPI32.DLL, with no high-signal malicious APIs (source: pe_imports import_count=3, signal_count=0).
3. **String-Based Detection**: Flag samples containing the `.themida` section marker string and high-entropy obfuscated static strings, plus strings referencing reverse engineering tools (source: floss strings, capa reference analysis tools rule).
4. **capa Integration**: Use capa's `packed with Themida` rule to automatically flag samples with confirmed Themida packing (source: capa top_rules).

## 11. What We Don't Know
The exact underlying malware family, payload capabilities, C2 server addresses, persistence mechanisms, and malicious behavior of the sample are unknown, as the Themida-packed payload was not dynamically unpacked and analyzed (source: deep_dive_agentic summary, llm_judge family_guess). Additional static analysis data from IDA and Malcat is unavailable due to missing tooling (idasql binary and malcat.mcp.py script respectively), so no additional structural or code analysis from those engines could be collected (source: llm_judge cross_engine_notes). YARA rule scanning was also unavailable due to a missing `yr` binary, so no YARA-based detection matches are available (source: Generated YARA Meta). Without successful unpacking of the Themida stub, no further details about the sample's malicious functionality can be determined.

## 12. Appendix: Analysis Environment
### Available Tools
- Ghidra (static code analysis, function/string extraction, import/export enumeration)
- capa (capability detection, ATT&CK/MBC mapping)
- FLOSS (string extraction, obfuscated string detection)
- pe_imports (import table enumeration, signal scoring)
- radare2 (disassembly, entry point analysis)
- Speakeasy (dynamic sandbox analysis, API call monitoring)
- Frida 17.16.4 (dynamic instrumentation probe)

### Unavailable Tools
- IDA: Missing `idasql` binary, no static analysis data collected from IDA (source: llm_judge cross_engine_notes)
- YARA: Missing `yr` binary, no rule scanning performed (source: Generated YARA Meta batch_errors)
- Malcat: Missing `/opt/malcat/bin/malcat.mcp.py` script, no deep profiling data collected (source: Malcat Structured Analysis error)
- UPX: Unpacking attempted but failed, sample is not UPX-packed (source: upx upx_ok=False, is_packed=False)
- Themida Unpacker: No dynamic unpacking tooling was available or used to extract the underlying payload, so no unpacked sample path exists (source: upx unpacked_path=``, deep_dive_agentic summary)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544  
**sample_path:** /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious, packed with Themida (ATT&CK T1027.002) to obfuscate a hidden malicious payload, with anti-analysis capabilities
- **score**: 88
- **family_guess**: Themida-packed malicious payload (likely common commodity malware such as a trojan, info-stealer, or ransomware; exact family cannot be determined without dynamic unpacking)
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA analysis was fully unavailable due to a missing idasql binary, so all static analysis is sourced from Ghidra, capa, FLOSS, and pe_imports. YARA scanning failed due to a missing yr binary, and Malcat deep profiling failed due to a missing malcat.mcp.py script. The Ghidra imports virtual table returned 0 rows, but DLL imports were identified via Ghidra's string list and corroborated by pe_imports' 3 import count. All available engines consistently indicate the sample is a Themida-packed binary with obfuscated content.
- **summary**: This sample is a Themida-packed malicious binary, as confirmed by multiple static analysis tools. capa identified Themida packing and associated decompression/anti-analysis behavior, FLOSS extracted a Themida-specific string, and Ghidra/pe_imports show a minimal import table and very low visible function/string counts consistent with packed binaries. No high-signal malicious imports were found, as the actual malicious functionality is hidden in the compressed payload that requires dynamic unpacking to analyze. IDA, YARA, and Malcat analysis were unavailable due to missing tooling, but available evidence is sufficient to classify the sample as malicious packed malware.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `"packed with Themida" rule (ATT&CK T1027.002, MBC F0001.011)` | capa's static analysis explicitly identified the sample as packed with Themida, a commercial packer widely used to obfus |
| floss | strings | `".themida" string entry` | FLOSS extracted a ".themida" string from the sample, directly corroborating capa's finding that the sample is packed wit |
| capa | top_rules | `"decompress data using aPLib" rule (MBC C0025.003)` | aPLib is a compression library commonly used by packers including Themida to compress original malicious payloads; this  |
| capa | top_rules | `"reference analysis tools strings" rule (MBC B0013.001)` | The sample contains strings referencing reverse engineering and analysis tools, a common anti-analysis technique used by |
| ghidra | Suspicious strings (Ghidra) | `Entries for "StringLoaderA.dll", "kernel32.dll", "USER32.dll", "ADVAPI32.dll"` | These are the only DLL imports present in the sample, consistent with a minimal Themida stub that only uses core Windows |
| pe_imports | import_count, signal_count | `import_count=3, signal_count=0` | The sample has only 3 total imports with no high-signal malicious APIs, which is typical of packed samples where the imp |
| ghidra | funcs, strings count | `funcs=25, strings=54` | The extremely low number of functions and visible strings in Ghidra analysis is consistent with a packed binary, where o |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 70
- **summary**: The sample is a Themida-packed PE. The `.themida` section is 4.7 MB of encrypted/compressed code with no readable strings. capa identifies Themida packing and aPLib decompression. Only three real imports are present (GetModuleHandleA, TranslateMessage, OpenProcessToken), and the entry function is highly complex (52 blocks, cyclomatic complexity 27), consistent with a VM/packer stub. A forwarded export `InitializeSecurity` is present. Without dynamic unpacking, the underlying payload behavior cannot be determined.

### deep key_evidence
- `"Ghidra memory block `.themida` at 0x268783616 size 4710400 perm=7 with no strings"`
- `"Ghidra imports: GetModuleHandleA (KERNEL32.DLL), TranslateMessage (USER32.DLL), OpenProcessToken (ADVAPI32.DLL)"`
- `"Ghidra funcs: entry size=336, blocks=52, cyclomatic_complexity=27; calls FUN_104d31a8"`
- `"Ghidra exports: forwarded export `InitializeSecurity`"`
- `"capa rules: packed with Themida (T1027.002), decompress data using aPLib (C0025.003)"`
- `"FLOSS strings include `.themida` section marker and high-entropy obfuscated strings"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 6 · duration_s: 36.38

| Rule | ATT&CK | MBC |
|---|---|---|
| packed with Themida | T1027.002:Obfuscated Files or Information | F0001.011:Software Packing |
| decompress data using aPLib |  | C0025.003:Decompress Data |
| forwarded export | T1129:Shared Modules |  |
| reference analysis tools strings |  | B0013.001:Analysis Tool Discovery |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

## PE Imports / Signals
import_count: 3

## Generated YARA Meta
```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ]
}
```

## FLOSS Strings
Total strings: 5014 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 5014}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `@.edata`
- `@.idata`
- `.themida`
- `'1~`nV9F`
- `\nxswz9C`
- `oh.n~L`
- `Uh~D8C`
- `?=RalLh	k`
- `'{,.L%J`
- `s\s`^#j`
- `"THnOt`
- `w7v:n#`
- `O0,Kd?`
- `|S0|N&`
- `&xK[#[`
- `INb@T%`
- `WWH~|Y`
- `h(&<ul`
- `{'z4(iBpH`
- `wl9T9Hb`
- `D!IBf,OX`
- `rc~]j"`
- `QH`l+[`
- `qrf4tv`
- `0rMjlUq`
- `cjCH%0`
- `g+Z?x`N`
- `T\bC8$`
- `g$y[Tc`
- `VrdE#"`
- `Q3e<KQ`
- `=h*kP?`
- `3eh1vZ`
- `H#+BV5`
- `v'+ST)`
- `[&@\0Q`
- `5Zw":!5`
- `#k][$o`
- `*Pt*XY`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x104d3058
```asm
┌ 336: entry0 ();
│           0x104d3058      e84b010000     call 0x104d31a8
│           0x104d305d      53             push ebx
│           0x104d305e      89e3           mov ebx, esp
│           0x104d3060      53             push ebx
│           0x104d3061      8b7308         mov esi, dword [ebx + 8]
│           0x104d3064      8b7b10         mov edi, dword [ebx + 0x10]
│           0x104d3067      fc             cld
│           0x104d3068      b280           mov dl, 0x80                ; 128
│       ┌─> 0x104d306a      8a06           mov al, byte [esi]
│       ╎   0x104d306c      46             inc esi
│       ╎   0x104d306d      8807           mov byte [edi], al
│       ╎   0x104d306f      47             inc edi
│       ╎   0x104d3070      bb02000000     mov ebx, 2
│       ╎   ; CODE XREFS from entry0 @ 0x104d30da(x), 0x104d3123(x), 0x104d3163(x), 0x104d3178(x), 0x104d3199(x)
│  ┌┌┌┌┌──> 0x104d3075      00d2           add dl, dl
│ ┌───────< 0x104d3077      7505           jne 0x104d307e
│ │╎╎╎╎╎╎   0x104d3079      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎╎   0x104d307b      46             inc esi
│ │╎╎╎╎╎╎   0x104d307c      10d2           adc dl, dl
│ └─────└─< 0x104d307e      73ea           jae 0x104d306a
│  ╎╎╎╎╎    0x104d3080      00d2           add dl, dl
│  ╎╎╎╎╎┌─< 0x104d3082      7505           jne 0x104d3089
│  ╎╎╎╎╎│   0x104d3084      8a16           mov dl, byte [esi]
│  ╎╎╎╎╎│   0x104d3086      46             inc esi
│  ╎╎╎╎╎│   0x104d3087      10d2           adc dl, dl
│ ┌─────└─> 0x104d3089      7351           jae 0x104d30dc
│ │╎╎╎╎╎    0x104d308b      31c0           xor eax, eax
│ │╎╎╎╎╎    0x104d308d      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d308f      7505           jne 0x104d3096
│ │╎╎╎╎╎│   0x104d3091      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d3093      46             inc esi
│ │╎╎╎╎╎│   0x104d3094      10d2           adc dl, dl
│ ──────└─> 0x104d3096      0f83e1000000   jae 0x104d317d
│ │╎╎╎╎╎    0x104d309c      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d309e      7505           jne 0x104d30a5
│ │╎╎╎╎╎│   0x104d30a0      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30a2      46             inc esi
│ │╎╎╎╎╎│   0x104d30a3      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30a5      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30a7      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30a9      7505           jne 0x104d30b0
│ │╎╎╎╎╎│   0x104d30ab      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30ad      46             inc esi
│ │╎╎╎╎╎│   0x104d30ae      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30b0      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30b2      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30b4      7505           jne 0x104d30bb
│ │╎╎╎╎╎│   0x104d30b6      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30b8      46             inc esi
│ │╎╎╎╎╎│   0x104d30b9      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30bb      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30bd      00d2   
```
### 0x10019110
```asm
┌ 110: sym.StringLoaderA.dll_InitializeSecurity (int32_t arg_65h);
│      ╎╎   ; arg int32_t arg_65h @ ebp+0x65
│      ╎╎   ; var int32_t var_3eh @ ebp-0x3e
│      ╎╎   0x10019110      2c52           sub al, 0x52                ; 82
│      ╎╎   0x10019112      54             push esp
│      ╎╎   0x10019113      50             push eax
│      ╎╎   0x10019114  ~   3ed09f6b59..   rcr byte ds:[edi - 0x43b3a695], 1
│     ┌───> 0x1001911a      bce63478ed     mov esp, 0xed7834e6
│     ╎ ╎   0x1001911f      b103           mov cl, 3
│     ╎ ╎   0x10019121      92             xchg edx, eax
│     ╎ ╎   0x10019122      baa6f7e81a     mov edx, 0x1ae8f7a6
│     ╎ ╎   0x10019127      6a03           push 3                      ; 3
│     ╎ ╎   0x10019129      3ea7           cmpsd dword ds:[esi], dword es:[edi]
│     ╎ ╎   0x1001912b      4c             dec esp
│     ╎ ╎   0x1001912c      1490           adc al, 0x90
│     ╎ ╎   0x1001912e      ff01           inc dword [ecx]
│     ╎ ╎   0x10019130      dabbd42fca48   fidivr dword [ebx + 0x48ca2fd4]
│     ╎ ╎   0x10019136      44             inc esp
│     └───< 0x10019137      7de1           jge 0x1001911a
│       ╎   0x10019139      a5             movsd dword es:[edi], dword [esi]
│       ╎   0x1001913a      bcfbb49fcd     mov esp, 0xcd9fb4fb
│      ┌──< 0x1001913f      787c           js 0x100191bd
│      │╎   0x10019141      62952f766976   bound edx, qword [ebp + 0x7669762f]
│      │╎   0x10019147      6d             insd dword es:[edi], dx
│      │╎   0x10019148      ed             in eax, dx
│      │╎   0x10019149      0cc4           or al, 0xc4                 ; 196
│      │╎   0x1001914b      5a             pop edx
│      │╎   0x1001914c      c165c2ff       shl dword [var_3eh], 0xff
│      │╎   0x10019150      94             xchg esp, eax
│      │╎   0x10019151      e7c5           out 0xc5, eax
│      │╎   0x10019153      9a12903ce8..   lcall 0xce34, 0xe83c9012
│      │╎   0x1001915a      b076           mov al, 0x76                ; 'v' ; 118
│      │╎   0x1001915c      0296ab586a57   add dl, byte [esi + 0x576a58ab]
│      │╎   0x10019162      9d             popfd
│      │╎   0x10019163      bd0776dc75     mov ebp, 0x75dc7607
│      │╎   0x10019168      57             push edi
│      │╎   0x10019169      2127           and dword [edi], esp
│      │╎   0x1001916b      df             invalid
..
│      └──> 0x100191bd      8e4565         mov es, word [arg_65h]
│       │   0x100191c0      ed             in eax, dx
│       │   0x100191c1      ca530a         retf 0xa53
..
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
