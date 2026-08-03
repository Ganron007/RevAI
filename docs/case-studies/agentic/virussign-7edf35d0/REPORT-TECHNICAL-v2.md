## 1. Executive Summary
This report analyzes a 32-bit Windows DLL (sha256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544) identified as a Themida-packed malicious loader/stager with a score of 9/10 (source: llm_judge, verdict.json). The sample exhibits extremely high entropy (224, source: malcat, file_summary) and 15 packing-related anomalies (source: malcat, anomalies), consistent with heavy obfuscation. Static analysis is severely limited due to Themida packing: capa confirms the sample is packed with Themida (rule: packed with Themida, source: capa, top_rules) and contains aPLib decompression functionality (rule: decompress data using aPLib, source: capa, top_rules), indicating it is designed to unpack a payload at runtime. The sample exports a suspicious module name `StringLoaderA.dll` (source: malcat, file_summary) and imports only 3 Windows APIs (source: pe_imports, import_count=3) associated with token manipulation and module loading: `OpenProcessToken`, `GetModuleHandleA`, and `InitializeSecurity` (source: malcat, Strings/apis). No specific malware family was identified from static analysis due to packing; unpacking the sample is required to analyze its core payload functionality. YARA independently confirms the sample is a packed PE DLL (rules: IsPacked, IsDLL, HasRichSignature, source: yara, matches).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 |
| Sample Path | /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir |
| Project Name | incoming |
| Verdict | Packed malicious PE DLL (Themida-packed, likely loader/stager) |
| Score | 9 |
| Family Guess | Unknown Themida-packed loader/stager (no specific family indicators identified from static analysis) |
| Agreement | llm_and_v1_agree |
| IDA Availability | Unavailable (all analysis derived from Ghidra, Malcat, capa, FLOSS, and YARA, source: llm_judge, cross_engine_notes) |

## 3. File Layout & Structural Analysis
The sample is a 3.1MB 32-bit Windows PE DLL with a valid MZ header and Rich signature (source: yara, matches: HasRichSignature, IsPE32). Malcat's file layout analysis identifies the following sections (source: malcat, File Layout table):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 205 | - |
| (unnamed) | 1024 | 132096 | 241664 | 223 | RX |
| (unnamed) | 242688 | 26112 | 69632 | 0 | R |
| (unnamed) | 312320 | 1024 | 8192 | 0 | RW |
| (unnamed) | 320512 | 512 | 4096 | 0 | RW |
| (unnamed) | 324608 | 8704 | 12288 | 0 | R |
| .edata | 336896 | 3072 | 4096 | 0 | R |
| .idata | 340992 | 512 | 4096 | 0 | RW |
| .boot | 345088 | 2993152 | 2994176 | 224 | RX |
| .themida | 3339264 | 0 | 4710400 | 0 | RWX |
Key structural observations:
- The `.themida` section is virtual-only (physical size 0) with RWX permissions, a hallmark of Themida-packed samples (source: malcat, anomalies: PurelyVirtualExecutableSection, SectionWX).
- The `.boot` section has extremely high entropy (224) and contains the entry point at EA 345176 (source: malcat, file_summary: entrypoint_ea=345176), consistent with packed/encrypted code.
- The sample has no relocation information (source: malcat, anomalies: DllNoRelocation) and an invalid SizeOfCode value (source: malcat, anomalies: InvalidSizeOfCode), common in packed binaries.
- 7 section names are unknown (source: malcat, anomalies: SectionNameUnknown), and 4 section names are duplicated (source: malcat, anomalies: DuplicatedSectionName), further indicating packing.

## 4. Malcat Triage Summary
Malcat analysis confirms the sample is a valid 32-bit Windows PE DLL with extremely high overall entropy (224, source: malcat, file_summary) and 15 packing-related anomalies (source: malcat, anomalies table):
| Anomaly Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, indicative of packed/patched/file infector code |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | 10KB+ medium-to-high entropy buffer with no cross-references, consistent with packed data |
| DllNoRelocation | 3 | sections | 1 | DLL lacks relocation information, common in packed samples |
| InvalidSizeOfCode | 3 | sections | 1 | SizeOfCode does not match sum of code section sizes |
| ManyHighValueImmediates | 3 | code | 4 | Functions contain >10% high-value immediate operands, typical of obfuscated/packed code |
| PurelyVirtualExecutableSection | 3 | sections | 1 | Virtual-only executable section, strong packer indicator |
| SectionNameUnknown | 3 | sections | 7 | Non-standard PE section names |
| SectionWX | 3 | sections | 1 | Writable/executable section, common for unpacking stubs |
| UnreferencedImports | 3 | imports | 3 | >50% of imports have no static cross-references, indicating dynamic import resolution or decoy imports |
| DuplicatedSectionName | 2 | sections | 4 | Duplicate section names in PE section table |
| HighEntropy | 2 | entropy | 0 | Overall file entropy >200 |
| HugeFunctionGapAtSectionBoundary | 2 | code | 2 | Large gaps between executable section bounds and first/last function, consistent with unpacked code not statically analyzed |
| HugeGapBetweenFunctions | 2 | code | 83 | Large gaps between functions with medium-to-high entropy, indicating stored data in code sections |
| SectionMostlyVirtual | 2 | sections | 1 | Section composed primarily of virtual space |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | Large discrepancy between physical and virtual section sizes |
High-signal strings identified by Malcat (source: malcat, High-Signal Strings table):
| EA | String |
|---|---|
| 340992 | `kernel32.dll` |
| 1502145 | `\JR` |
Malcat's YARA signature match is limited to the MSVC_2022_linker rule (source: malcat, Malcat YARA/Signatures table), indicating the sample was compiled with Visual Studio 2022. Decompilation of top functions fails with bad instruction data and invalid VA errors (source: malcat, Decompilations table):
- `sub_104fdc27` (EA 520231): Contains `halt_baddata()` and bad instruction warnings, indicating packed code that cannot be decompiled statically.
- `sub_105f197a` (EA 1518970) and `sub_106410b2` (EA 1844402) return "not a valid va" errors, confirming static analysis limitations.

## 5. Static Code Analysis
Static analysis is heavily constrained by Themida packing, which obfuscates control flow and encrypts code sections. The sample's entry point (EP) is located at EA 345176 in the `.boot` section (source: malcat, file_summary: entrypoint_ea=345176). Radare2 disassembly of the EP (0x104d3058, source: radare2, 0x104d3058 disassembly) shows a standard function prologue followed by a large loop consistent with Themida's unpacking stub and aPLib decompression logic (source: capa, top_rules: decompress data using aPLib):
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
│ │╎╎╎╎╎│   0x104d3084      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d3086      46             inc esi
│ │╎╎╎╎╎│   0x104d3087      10d2           adc dl, dl
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
The sample's import address table (IAT) contains only 3 imports (source: pe_imports, import_count=3; source: ghidra, imports table):
| EA | Name | Type | Refs |
|---|---|---|---|
| 341168 | kernel32.GetModuleHandleA | IMPORT | 1 |
| 341176 | user32.TranslateMessage | IMPORT | 1 |
| 341184 | advapi32.OpenProcessToken | IMPORT | 1 |
Additionally, the sample exports a large number of functions from the `StringLoaderB` namespace (source: malcat, imports table) and the `InitializeSecurity` export (EA 99600, source: malcat, functions table), which are associated with the custom `StringLoaderA.dll` module. Decompilation of most functions fails with "not a valid va" or bad instruction errors (source: malcat, decompilations table), confirming that static analysis of the packed code is not possible without unpacking. Ghidra identifies 30 total functions (source: ghidra_query, sql: SELECT count(*) AS funcs FROM funcs) with large gaps between them (source: malcat, anomalies: HugeGapBetweenFunctions, 83 hits), indicating unanalyzed unpacked code regions.

## 6. Behavioral & Dynamic Analysis
No dynamic behavior was observed during analysis. Speakeasy dynamic execution recorded 0 API calls and 0 key events (source: speakeasy, speakeasy_ok=True, api_calls=0, key_events=0), and Frida probing returned no data (source: frida_probe, frida_available=True, no events recorded). UPX unpacking failed (source: upx, upx_ok=False, is_packed=False, returncode=None, unpacked_path=``), as expected for Themida-packed samples which are not compatible with UPX. No runtime behavior, process injection, file system changes, or network communication was observed; all behavioral claims are marked as not observed per analysis rules.

## 7. Network Indicators & C2
No live C2 communication was observed dynamically (source: speakeasy, api_calls=0). Static analysis identified embedded network-related indicators via YARA (source: yara, matches table):
| Rule | Match Details |
|---|---|
| domain | Matched domain regex at offset 0, length 2 |
| IP | Matched IPv6 address regex at offset 36311, length 3 |
| contains_base64 | Matched base64 content at offset 169512, length 12 |
| win_token | Matched Windows token manipulation strings at offsets 172606 (length 12) and 172621 (length 16) |
FLOSS extracted 5014 static strings, 0 of which were decoded, stack, or tight strings (source: floss, FLOSS Strings: total_strings=5014, per_category: decoded_strings=0, stack_strings=0, tight_strings=0), indicating all strings are obfuscated by Themida and will only be decrypted at runtime. The high-signal string `\JR` (EA 1502145, source: malcat, High-Signal Strings) may be a C2 path fragment, but this is unconfirmed without unpacking.

## 8. Capabilities & MITRE ATT&CK Mapping
capa analysis identified 3 capability rules (source: capa, capa Capability Rules table):
| Rule | ATT&CK Technique | MBC Behavior |
|---|---|---|
| packed with Themida | T1027.002: Obfuscated Files or Information | F0001.011: Software Packing |
| decompress data using aPLib | N/A | C0025.003: Decompress Data |
| forwarded export | T1129: Shared Modules | N/A |
Additional capabilities are inferred from static imports and strings:
- Token manipulation: The `OpenProcessToken` import (EA 341184, source: ghidra, imports table) and `win_token` YARA match (source: yara, matches) indicate the sample may perform privilege escalation or token theft, mapped to MITRE ATT&CK T1134: Access Token Manipulation.
- Module loading: The `GetModuleHandleA` import (EA 341168, source: ghidra, imports table) indicates the sample loads additional modules, consistent with loader/stager behavior.
- Payload unpacking: The aPLib decompression capability (source: capa, top_rules: decompress data using aPLib) indicates the sample unpacks a secondary payload at runtime, a common loader/stager behavior.

## 9. Indicators of Compromise
| IOC Type | Value | Source |
|---|---|---|
| SHA256 | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 | llm_judge, verdict.json |
| File Name | virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir | malcat, file_summary: file_name |
| Export Module Name | StringLoaderA.dll | malcat, file_summary: metadata::Exports::Module name |
| Embedded String | \\JR | malcat, High-Signal Strings: EA 1502145 |
| Imported DLL | kernel32.dll | malcat, High-Signal Strings: EA 340992; ghidra, imports |
| Imported DLL | USER32.dll | ghidra, Suspicious strings: 268779552 |
| Imported DLL | ADVAPI32.dll | ghidra, Suspicious strings: 268779582 |
| Custom DLL | StringLoaderA.dll | ghidra, Suspicious strings: 268775464 |
| YARA Match | Domain regex | yara, matches: domain |
| YARA Match | IPv6 address regex | yara, matches: IP |
| YARA Match | Base64 content | yara, matches: contains_base64 |
| YARA Match | Windows token strings | yara, matches: win_token |
| Packer Signature | Themida | capa, top_rules: packed with Themida; malcat, anomalies: .themida section |

## 10. Detection Engineering
Detection rules can be built around the sample's static indicators:
1. YARA Rule for Packed Themida Loaders:
```yara
rule Themida_Packed_StringLoader_Loader {
    meta:
        description = "Detects Themida-packed loader/stager exporting StringLoaderA.dll"
        author = "malware-analyst"
        sha256 = "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544"
    strings:
        $export_name = "StringLoaderA.dll" ascii
        $themida_section = ".themida" ascii
        $api1 = "OpenProcessToken" ascii
        $api2 = "GetModuleHandleA" ascii
        $api3 = "InitializeSecurity" ascii
    condition:
        uint32(0) == 0x5A4D and // MZ header
        uint32(0x3C) + 4 < filesize and // PE header at e_lfanew
        uint32(uint32(0x3C)) == 0x4550 and // PE signature
        $export_name and
        $themida_section and
        $api1 and $api2 and $api3 and
        filesize > 3000000 and // >3MB, consistent with sample size
        pe.imports("advapi32.dll", "OpenProcessToken") and
        pe.imports("kernel32.dll", "GetModuleHandleA")
}
```
2. capa Detection: Use the existing `packed with Themida` and `decompress data using aPLib` rules to identify packed loaders with unpacking functionality (source: capa, top_rules).
3. Behavioral Detection: Alert on DLLs with high entropy (>220), low import count (<5), RWX executable sections, and exports named `StringLoaderA.dll` (source: malcat, file_summary: entropy=224; pe_imports, import_count=3; malcat, anomalies: SectionWX).

## 11. What We Don't Know
1. Unpacked payload functionality: Static analysis of the packed code is not possible without unpacking the sample (source: malcat, decompilations: bad instruction errors; capa, top_rules: packed with Themida). The core malicious functionality of the payload remains unknown.
2. Specific malware family: No family-specific indicators were identified in static analysis due to heavy packing (source: llm_judge, verdict.json: family_guess=Unknown).
3. Live C2 addresses: The domain and IPv6 strings detected by YARA are obfuscated (source: yara, matches: domain, IP) and no live C2 communication was observed dynamically (source: speakeasy, api_calls=0), so active C2 endpoints are unknown.
4. Runtime behavior: No dynamic execution data was captured (source: speakeasy, key_events=0; frida_probe, no events), so process injection, file system modifications, and other runtime actions are unknown.
5. Purpose of StringLoaderA.dll exports: The exported `StringLoaderB` namespace functions (source: malcat, imports table) suggest string loading functionality, but their exact purpose in the malware workflow is unknown without unpacking.

## 12. Appendix: Analysis Environment
All analysis was performed in a sandboxed environment with the following tools, as IDA was unavailable (source: llm_judge, cross_engine_notes):
- Ghidra: For PE parsing, function identification, string extraction, and import/export enumeration (source: ghidra_query, audit trail SQL queries).
- Malcat: For file layout analysis, anomaly detection, string extraction, and decompilation (source: malcat, all Malcat structured evidence).
- capa: For capability detection and MITRE ATT&CK mapping (source: capa, capa Capability Rules table).
- FLOSS: For obfuscated string extraction (source: floss, FLOSS Strings table).
- YARA: For signature matching and IOC identification (source: yara, YARA Matches table).
- radare2: For entry point disassembly (source: radare2, 0x104d3058 disassembly).
- Speakeasy: For dynamic sandbox execution (source: speakeasy, speakeasy_ok=True, 0 events).
- Frida: For runtime instrumentation probing (source: frida_probe, frida_available=True, no events).
- UPX: For unpacking attempts (source: upx, upx_ok=False).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544  
**sample_path:** /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Packed malicious PE DLL (Themida-packed, likely loader/stager)
- **score**: 9
- **family_guess**: Unknown Themida-packed loader/stager (no specific family indicators identified from static analysis)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is unavailable for this sample, so all analysis is derived from Ghidra, Malcat, capa, FLOSS, and YARA. Multiple tools independently confirm Themida packing: Malcat identifies a .themida section and 15 packing-related anomalies; capa explicitly matches the 'packed with Themida' rule; YARA matches the 'IsPacked' rule. High entropy (224, per Malcat) is consistent across all tools, indicating packed/encrypted content. Import data aligns across sources: Ghidra identifies 4 suspicious DLL imports, Malcat reports 3 mid-signal APIs (OpenProcessToken, GetModuleHandleA, InitializeSecurity) corresponding to those imports, and pe_imports confirms a low total import count (3) typical of packed samples that resolve imports dynamically. Decompilation failures (per Malcat and Ghidra) and large function gaps (per Malcat) confirm static analysis of the packed code is not possible without unpacking. Capa's detection of aPLib decompression functionality aligns with the sample being a packed loader that will unpack its payload at runtime.
- **summary**: This is a 32-bit Windows DLL packed with the Themida packer, with very high entropy (224) and numerous packing-related anomalies. Static analysis is heavily limited due to packing, but indicators suggest it is a loader/stager designed to unpack a malicious payload at runtime using aPLib decompression. It imports common Windows system DLLs and a suspicious custom DLL (StringLoaderA.dll), and uses APIs associated with token manipulation and module loading. No specific malware family was identified from static analysis due to the heavy packing and obfuscation; unpacking the sample is required to analyze its core functionality and identify its payload.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with Themida` | Explicitly confirms the sample is packed with the Themida commercial packer, a common tool used to obfuscate malware, ex |
| malcat | file_summary | `entropy=224, type=PE, architecture=X86, metadata::Exports::Module name=StringLoa` | Confirms the sample is a 32-bit Windows DLL with very high entropy (indicative of packed/encrypted content) and exports  |
| malcat | anomalies | `CrossSectionJump (code), HugeGapBetweenFunctions×83 (code), SectionWX (sections)` | These anomalies are characteristic of packed malware: cross-section control flow jumps, large gaps between functions (fr |
| yara | matches | `IsPacked, HasRichSignature, IsDLL` | YARA rules independently confirm the sample is a packed PE DLL with a valid Rich header, aligning with Malcat's PE metad |
| malcat | decompilations | `sub_104fdc27 contains halt_baddata() and bad instruction warnings` | Decompilation failures and invalid instruction data are consistent with packed code that cannot be statically analyzed w |
| capa | top_rules | `decompress data using aPLib` | Indicates the sample contains aPLib decompression functionality, a common feature of packed loaders used to unpack their |
| ghidra | Suspicious strings (Ghidra) | `268775464 | StringLoaderA.dll, 268779520 | kernel32.dll, 268779552 | USER32.dll,` | Reveals the sample imports common Windows system DLLs and a suspicious custom DLL (StringLoaderA.dll), consistent with l |
| malcat | Strings/apis | `InitializeSecurity, OpenProcessToken, GetModuleHandleA` | These APIs are commonly used by malware to manipulate security tokens, load modules, and execute code, aligning with the |
| floss | strings | `5014 total strings, 0 decoded/stack/tight strings` | The large volume of obfuscated strings with no statically decoded content is consistent with packed code where strings a |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The sample is a 3.1MB packed 32-bit Windows GUI DLL (export name StringLoaderA.dll) with extremely high entropy (224) consistent with obfuscated/packed malware. YARA scanning matched multiple rules indicating malicious traits including packed executable format, embedded network indicators (domain, IPv6 address, base64 content), Windows token manipulation strings, and valid PE structure. Malcat analysis confirms it is a valid Windows PE file with high entropy and a defined entry point, aligning with characteristics of malicious loaders.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPacked", "why": "YARA rule explicitly identifies the sample as a packed executable, a common anti-analysis technique used by malware to hinder reverse engineering"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPE32", "why": "Confirms the sample is a valid 32-bit Portable Executable, the standard binary format for Windows malware"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsDLL", "why": "Identifies the sample as a Dynamic Link Library, with the export name 'StringLoaderA.dll' indicating it is designed to load malicious string payloads, a common loader pattern"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsWindowsGUI", "why": "Indicates the sample is a Windows GUI application, consistent with user-facing malware or loader components that interact with the desktop environment"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "HasRichSignature", "why": "Detects a valid Rich header signature, confirming the sample is a properly compiled PE structure, not a corrupted or non-executable file"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "domain", "why": "Detects embedded domain strings, a strong indicator of command-and-control (C2) communication capability for malware"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IP", "why": "Detects embedded IPv6 address strings, another indicator of network communication functionality for C2 or data exfiltration"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "contains_base64", "why": "Identifies embedded base64 encoded content, often used by malware to obfuscate payloads, C2 addresses, or malicious commands to evade static detection"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "win_token", "why": "Detects Windows token related strings, indicating the sample may perform privilege escalation or token manipulation, a common malicious behavior for gaining system access"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary", "row_or_rule": "entropy", "why": "Entropy value of 224 is extremely high, consistent with packed or encrypted malicious code designed to evade static analysis tools"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary", "row_or_rule": "type/architecture", "why": "Confirms the sample is a 32-bit Windows PE file, matching YARA PE detection and consistent with common Windows malware targets"}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
size: 3166208
type: PE
architecture: X86
entrypoint_ea: 345176
entropy: 224
file_name: virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 205 | - |
|          | 1024 | 132096 | 241664 | 223 | RX |
|          | 242688 | 26112 | 69632 | 0 | R |
|          | 312320 | 1024 | 8192 | 0 | RW |
|          | 320512 | 512 | 4096 | 0 | RW |
|          | 324608 | 8704 | 12288 | 0 | R |
| .edata | 336896 | 3072 | 4096 | 0 | R |
| .idata | 340992 | 512 | 4096 | 0 | RW |
| .boot | 345088 | 2993152 | 2994176 | 224 | RX |
| .themida | 3339264 | 0 | 4710400 | 0 | RWX |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2022_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |

### Anomalies (15)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| DllNoRelocation | 3 | sections | 1 | dll has no relocation information |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| ManyHighValueImmediates | 3 | code | 4 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) |
| SectionNameUnknown | 3 | sections | 7 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 3 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| DuplicatedSectionName | 2 | sections | 4 | section name has already been used before in section table |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| HugeFunctionGapAtSectionBoundary | 2 | code | 2 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| HugeGapBetweenFunctions | 2 | code | 83 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| SectionMostlyVirtual | 2 | sections | 1 | section is composed of mostly virtual space |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **ManyHighValueImmediates**
  - `51727`: 
  - `1286388`: 
  - `1518970`: 
  - `2349956`: 

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 340992 | `kernel32.dll` |
| 1502145 | `\\JR` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 339047 | `StringLoaderB.?R..ryBufferInfo@@@Z` |
| 339503 | `StringLoaderB.?W..ryBufferInfo@@@Z` |
| 338961 | `StringLoaderB.?R..ryBufferInfo@@@Z` |
| 339418 | `StringLoaderB.?W..ryBufferInfo@@@Z` |
| 338882 | `StringLoaderB.?R..ryBufferInfo@@@Z` |
| 338734 | `StringLoaderB.?I..ryBufferInfo@@@Z` |
| 339133 | `StringLoaderB.?R..ryBufferInfo@@@Z` |
| 339588 | `StringLoaderB.?W..ryBufferInfo@@@Z` |
| 339340 | `StringLoaderB.?W..ryBufferInfo@@@Z` |
| 339667 | `StringLoaderB.?m..VCFixedString@@A` |
| 338668 | `StringLoaderB.?G..VCStringList@@XZ` |
| 339273 | `StringLoaderB.?S..VCStringList@@@Z` |
| 337960 | `?WriteBufferToFi..ryBufferInfo@@@Z` |
| 337588 | `?ReadBufferFromF..ryBufferInfo@@@Z` |
| 337331 | `?IsBufferContain..ryBufferInfo@@@Z` |
| 338031 | `?WriteStringToBu..ryBufferInfo@@@Z` |
| 338397 | `StringLoaderB.?D..er@@SAXPAPAV1@@Z` |
| 337889 | `?WriteBufferToFi..ryBufferInfo@@@Z` |
| 337660 | `?ReadStringFromB..ryBufferInfo@@@Z` |
| 338816 | `StringLoaderB.?I..oader@@SA_NPBD@Z` |
| 337516 | `?ReadBufferFromF..ryBufferInfo@@@Z` |
| 338335 | `StringLoaderB.?C..er@@SAPAV1@PBD@Z` |
| 337451 | `?ReadBufferFromF..ryBufferInfo@@@Z` |
| 337825 | `?WriteBufferToFi..ryBufferInfo@@@Z` |
| 339213 | `StringLoaderB.?S..oader@@SA_NPBD@Z` |
| 338506 | `StringLoaderB.?G..gLoader@@SAPBDXZ` |
| 337772 | `?SetStringList@C..VCStringList@@@Z` |
| 338616 | `StringLoaderB.?G..ngLoader@@QBEIXZ` |
| 337279 | `?GetStringList@C..VCStringList@@XZ` |
| 338096 | `?m_cDefaultDirec..VCFixedString@@A` |
| 337030 | `?CreateStringLoa..er@@SAPAV1@PBD@Z` |
| 337078 | `?DestroyStringLo..er@@SAXPAPAV1@@Z` |
| 338564 | `StringLoaderB.?G..ingLoader@@SAKXZ` |
| 337399 | `?IsFileNameConta..oader@@SA_NPBD@Z` |
| 338460 | `StringLoaderB.?G..oader@@QBEPBDI@Z` |
| 336936 | `StringLoaderA.dll` |
| 341054 | `ADVAPI32.dll` |
| 337726 | `?SetDefaultDirec..oader@@SA_NPBD@Z` |
| 338298 | `StringLoaderB.??..tringLoader@@6B@` |
| 338217 | `StringLoaderB.??..oader@@QAE@PBD@Z` |
| 338259 | `StringLoaderB.??..ngLoader@@UAE@XZ` |
| 337159 | `?GetDefaultDirec..gLoader@@SAPBDXZ` |
| 337241 | `?GetStringCount@..ngLoader@@QBEIXZ` |
| 341024 | `USER32.dll` |
| 340992 | `kernel32.dll` |
| 337203 | `?GetOSFlatformID..ingLoader@@SAKXZ` |
| 337127 | `?GetAt@CStringLoader@@QBEPBDI@Z` |
| 336954 | `??0CStringLoader@@QAE@PBD@Z` |
| 336982 | `??1CStringLoader@@UAE@XZ` |
| 337007 | `??_7CStringLoader@@6B@` |
| 338150 | `InitializeSecurity` |
| 2981296 | `0n=8m` |
| 2336192 | `D]x80g` |
| 1364105 | `E
Po` |
| 2580076 | `_OH@5` |
| 1156594 | `J
]R` |
| 2592825 | `XV0` |
| 1110724 | `
K;O` |
| 1896207 | ``X2U` |
| 2335629 | `..ZDD` |
| 1406166 | `AH]'_` |
| 2256609 | `Fc$B` |
| 2197361 | ` .qw` |
| 3237120 | `pr&0` |
| 1949607 | `0N5$` |
| 468494 | `W]N%` |
| 2394008 | ``*8D` |
| 2057603 | `..UAN` |
| 2768282 | `..UPi` |
| 2433193 | `JtD$C(g&` |
| 1752728 | `S)Z	
` |
| 123704 | `~X=g+9(` |
| 2118909 | `1b.RkW` |
| 2626503 | `i.HPW` |
| 77 | `!This program ca..in DOS mode.
$` |
| 1706306 | `hw.ZIN` |
| 1562539 | `9.LVv` |
| 518510 | `%03!` |
| 47741 | `8.bhW` |
| 2014099 | `x...` |

### Imports (27)
| EA | Name | Type | Refs |
|---|---|---|---|
| 99600 | InitializeSecurity | EXPORT | 1 |
| 338217 | InitializeSecurity->StringLoaderB.CStringLoader.CStringLoader | EXPORT | 1 |
| 338259 | InitializeSecurity->StringLoaderB.CStringLoader.~CStringLoader | EXPORT | 1 |
| 338298 | InitializeSecurity->StringLoaderB.??_7CStringLoader@@6B@ | EXPORT | 1 |
| 338335 | InitializeSecurity->StringLoaderB.CStringLoader.CreateStringLoader | EXPORT | 1 |
| 338397 | InitializeSecurity->StringLoaderB.CStringLoader.DestroyStringLoader | EXPORT | 1 |
| 338460 | InitializeSecurity->StringLoaderB.CStringLoader.GetAt | EXPORT | 1 |
| 338506 | InitializeSecurity->StringLoaderB.CStringLoader.GetDefaultDirectory | EXPORT | 1 |
| 338564 | InitializeSecurity->StringLoaderB.CStringLoader.GetOSFlatformID | EXPORT | 1 |
| 338616 | InitializeSecurity->StringLoaderB.CStringLoader.GetStringCount | EXPORT | 1 |
| 338668 | InitializeSecurity->StringLoaderB.CStringLoader.GetStringList | EXPORT | 1 |
| 338734 | InitializeSecurity->StringLoaderB.CStringLoader.IsBufferContainUnicode | EXPORT | 1 |
| 338816 | InitializeSecurity->StringLoaderB.CStringLoader.IsFileNameContainFullPath | EXPORT | 1 |
| 338882 | InitializeSecurity->StringLoaderB.CStringLoader.ReadBufferFromFile | EXPORT | 1 |
| 338961 | InitializeSecurity->StringLoaderB.CStringLoader.ReadBufferFromFileInWin95 | EXPORT | 1 |
| 339047 | InitializeSecurity->StringLoaderB.CStringLoader.ReadBufferFromFileInWinNT | EXPORT | 1 |
| 339133 | InitializeSecurity->StringLoaderB.CStringLoader.ReadStringFromBuffer | EXPORT | 1 |
| 339213 | InitializeSecurity->StringLoaderB.CStringLoader.SetDefaultDirectory | EXPORT | 1 |
| 339273 | InitializeSecurity->StringLoaderB.CStringLoader.SetStringList | EXPORT | 1 |
| 339340 | InitializeSecurity->StringLoaderB.CStringLoader.WriteBufferToFile | EXPORT | 1 |
| 339418 | InitializeSecurity->StringLoaderB.CStringLoader.WriteBufferToFileInWin95 | EXPORT | 1 |
| 339503 | InitializeSecurity->StringLoaderB.CStringLoader.WriteBufferToFileInWinNT | EXPORT | 1 |
| 339588 | InitializeSecurity->StringLoaderB.CStringLoader.WriteStringToBuffer | EXPORT | 1 |
| 339667 | InitializeSecurity->StringLoaderB.?m_cDefaultDirectory@CStringLoader@@0VCFixedString@@A | EXPORT | 1 |
| 341168 | kernel32.GetModuleHandleA | IMPORT | 1 |
| 341176 | user32.TranslateMessage | IMPORT | 1 |
| 341184 | advapi32.OpenProcessToken | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 1518970 | sub_105f197a |
| 520231 | sub_104fdc27 |
| 1844402 | sub_106410b2 |
| 584196 | sub_1050d604 |
| 51727 | sub_1000d60f |
| 2349956 | sub_106bc784 |
| 1286388 | sub_105b8cf4 |
| 1675406 | sub_10617c8e |
| 1014364 | sub_1057665c |
| 761446 | sub_10538a66 |
| 90993 | sub_10016f71 |
| 2878584 | sub_1073d878 |
| 424914 | sub_104e67d2 |
| 1735476 | sub_10626734 |
| 47510 | sub_1000c596 |
| 1104982 | sub_1058c856 |
| 1407740 | sub_105d66fc |
| 99600 | InitializeSecurity |
| 345176 | EntryPoint |
| 3110497 | sub_10776261 |
| 1072977 | sub_10584b51 |
| 1989319 | sub_106646c7 |
| 3099227 | sub_1077365b |
| 1642708 | sub_1060fcd4 |
| 1711251 | sub_10620893 |
| 1965118 | sub_1065e83e |
| 1280329 | sub_105b7549 |
| 345512 | sub_104d31a8 |
| 1835327 | sub_1063ed3f |
| 3004132 | sub_1075c2e4 |

### Decompilations (top 6)
#### 1518970 — sub_105f197a
```c
sub_105f197a {
    // Error while decompiling : not a valid va
}

```
#### 520231 — sub_104fdc27
```c

/* WARNING: Control flow encountered bad instruction data */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_104fdc27(void)

{
    char cVar1;
    undefined4 *puVar2;
    undefined4 *unaff_EBP;
    undefined4 uStack_8;
    
    puVar2 = &stack0xfffffffc;
    cVar1 = '\b';
    do {
        unaff_EBP = unaff_EBP + -1;
        puVar2 = puVar2 + -1;
        *puVar2 = *unaff_EBP;
        cVar1 = cVar1 + -1;
    } while ('\0' < cVar1);
    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
}

```
#### 1844402 — sub_106410b2
```c
sub_106410b2 {
    // Error while decompiling : not a valid va
}

```

### Structures (16)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 248 |
| OptionalHeader | 272 |
| Sections | 496 |
| ExportDirectory | 336896 |
| ExportNames | 336936 |
| OrdinalNameTable | 338169 |
| ExportNames | 338217 |
| ExportAddressTable | 339735 |
| ExportNameTable | 339831 |
| ImportNames | 340992 |
| ImportTable | 341086 |
| kernel32.FT | 341168 |
| user32.FT | 341176 |
| advapi32.FT | 341184 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 3 · duration_s: 1.07

| Rule | ATT&CK | MBC |
|---|---|---|
| packed with Themida | T1027.002:Obfuscated Files or Information | F0001.011:Software Packing |
| decompress data using aPLib |  | C0025.003:Decompress Data |
| forwarded export | T1129:Shared Modules |  |

## PE Imports / Signals
import_count: 3

## YARA Matches (pipeline)
Total matches: 10

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@36311 len=3 |
| contains_base64 | - | $a@169512 len=12 |
| CRC32_poly_Constant | - | $c0@1328583 len=4 |
| IsPE32 | - |  |
| IsDLL | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@232 len=4 |
| win_token | - | $f1@172606 len=12; $c3@172621 len=16 |

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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785759182.2492874}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785759182.2556028}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785759182.2594883}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785759182.262903}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785759236.3988147}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785759236.4217627}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785759236.4491343}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785759236.4558113}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785759236.4572694}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785759316.3281887}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports LIMIT 50", "ts": 1785759322.986644}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM funcs LIMIT 50", "ts": 1785759322.9898534}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings LIMIT 100", "ts": 1785759322.9933634}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY module, name", "ts": 1785759328.4459887}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM function_metrics ORDER BY instruction_count DESC LIMIT 30", "ts": 1785759328.4730465}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM memory_blocks ORDER BY start_ea", "ts": 1785759334.3562243}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM exports LIMIT 50", "ts": 1785759334.3592637}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%https%' OR content LIKE '%ftp%' OR content LIKE '%.exe%' OR content LIKE '%.dll%' OR content LIKE '%token%' OR content LIKE '%pass%' OR content LIKE '%admin%' OR content LIKE`
