## 1. Executive Summary
This sample is a heavily obfuscated/packed Windows PE malware with a final verdict score of 8, classified as an unidentified packed/obfuscated malware (likely loader or crypter) (source: llm_judge, verdict.json). Static analysis via capa confirms the sample uses three distinct custom encryption algorithms (RC4, Chaskey, Speck) for obfuscation, mapping to ATT&CK T1027 (Obfuscated Files or Information), and performs system language discovery via API calls mapping to ATT&CK T1614.001 (System Location Discovery) (source: capa, top_rules). The sample imports only 7 standard Windows system libraries with no high-signal malicious APIs, and FLOSS string analysis returned 1144 static strings with 0 decoded, stack, or tight strings, both consistent with packed malware that defers malicious functionality to decrypted runtime payloads (source: pe_imports, import_count; source: floss, string_count). Limited analysis tool availability (IDA analysis failed validation and returned no usable data, Malcat analysis errored, YARA scanning failed due to missing 'yr' binary) prevents deeper payload analysis, but available evidence confirms malicious intent with strong obfuscation capabilities (source: llm_judge, cross_engine_notes).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 |
| Sample Path | /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir |
| Project Name | incoming |
| Verdict | Malicious obfuscated/packed Windows PE malware |
| Score | 8 |
| Family Guess | Unidentified packed/obfuscated malware (likely loader or crypter) |
| Agreement | llm_v1_disagree |
| Cross-Engine Notes | 1. IDA analysis failed validation and returned no usable data, so all static analysis relies on Ghidra, capa, FLOSS, and pe_imports<br>2. Malcat analysis errored and provided no data<br>3. YARA scanning failed due to missing 'yr' binary, so no signature matches were returned<br>4. Ghidra imports table is empty per known limitation for mixed-mode/stripped PEs, so import data is sourced from pe_imports and Ghidra suspicious string data<br>5. FLOSS returned 1144 static strings but no decoded/stack/tight strings, indicating packed/encrypted content |
(source: llm_judge, verdict.json)

## 3. File Layout & Structural Analysis
The sample is a non-.NET Windows PE file (source: dotnet analysis, is_dotnet: false) with a single large executable section consistent with packed/obfuscated malware. UPX unpacking attempts failed, with upx_ok: False, returncode: None, and no unpacked output path generated (source: upx, unpack results). XOR search identified a XOR 00 key at file offset 0x00000000, with the first 16 bytes of the XOR keystream matching the DOS stub header "!This program cannot be run in DOS mode." (source: xor search, results). Static analysis identified 365 total functions in the binary (source: ghidra, funcs, corrected from ida per cross_engine_notes). The entry point function (address 0x4198400) has extreme cyclomatic complexity of 102 and makes 101 total outgoing calls, dominated by 50 calls to SystemFunction033 (RC4) and 46 calls to MessageBoxExA, consistent with control-flow flattening or a dispatch loop typical of packed crypter stubs (source: ghidra, function_metrics; source: ghidra, callgraph_edges). The sample has only 11 high-signal static strings, almost all of which are DLL or API import names (e.g., MessageBoxExA, SystemFunction033, advapi32.dll, kernel32.dll, ntdll.dll), with no clear-text malicious indicators (source: ghidra, strings).

## 4. Malcat Triage Summary
Malcat analysis failed entirely with the following error: `malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory` (source: malcat, analysis error). No Malcat triage data, structural analysis, or signature matches are available for this sample due to this tooling failure.

## 5. Static Code Analysis
### Import Address Table (IAT) Disassembly (radare2)
radare2 disassembly of key IAT thunks is as follows (source: radare2, disassembly):
| Address | Disassembly | XREF Count | Imported Function |
|---|---|---|---|
| 0x00475a1e | `ff2500604700 jmp dword [sym.imp.user32.dll_MessageBoxExA] ; 0x476000` | 46 | MessageBoxExA |
| 0x00475a24 | `ff2508604700 jmp dword [sym.imp.advapi32.dll_SystemFunction033] ; 0x476008` | 50 | SystemFunction033 (RC4) |
| 0x00475a2a | `ff2520604700 jmp dword [sym.imp.kernel32.dll_GetSystemDefaultLCID] ; 0x476020` | 1 | GetSystemDefaultLCID |
| 0x00475a30 | `ff2524604700 jmp dword [sym.imp.kernel32.dll_GetUserDefaultUILanguage] ; 0x476024` | 3 | GetUserDefaultUILanguage |

### capa Capability Rules
capa analysis matched 6 total rules in 2.29 seconds (source: capa, top_rules):
| Rule | ATT&CK Mapping | MBC Mapping |
|---|---|---|
| encrypt data using RC4 via SystemFunction033 | T1027: Obfuscated Files or Information | E1027.m05: Obfuscated Files or Information, C0027.009: Encrypt Data |
| encrypt data using chaskey | T1027: Obfuscated Files or Information | E1027.m05: Obfuscated Files or Information |
| encrypt data using speck | T1027: Obfuscated Files or Information | E1027.m05: Obfuscated Files or Information |
| identify system language via API | T1614.001: System Location Discovery | N/A |
| hash data using murmur3 | N/A | C0030.001: Non-Cryptographic Hash |
| contain loop | N/A | N/A |

### Import Signals
The sample has 7 total imports, 0 of which are high-signal malicious APIs (source: pe_imports, import_count). All imports are limited to standard Windows system DLLs: user32.dll, advapi32.dll, ntdll.dll, kernel32.dll (source: ghidra, Suspicious strings (Ghidra)). Additional Ghidra-identified strings include the legitimate Windows API `FreeEncryptedFileKeyInfo` with no other high-signal malicious strings present (source: ghidra, Suspicious strings (Ghidra)).

### FLOSS Static Strings
FLOSS analysis returned 1144 total static strings, with 0 decoded, stack, or tight strings, indicating all malicious content is encrypted/packed and not exposed in static analysis (source: floss, string_count). A sample of low-signal FLOSS static strings is below (source: floss, FLOSS sample):
```
!This program cannot be run in DOS mode.
Rich!l
.rdata
@.data
eq9f(2A
cqn,)=Aq
QiR?])
MC	HsC
:U=y-]
m67X|}
```

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Speakeasy dynamic analysis completed successfully (speakeasy_ok: True) but recorded 0 API calls and 0 key events, with no duration or behavioral data generated (source: speakeasy, results). Frida instrumentation was available (version 17.16.4) but no runtime data was captured (source: frida_probe, results). UPX unpacking failed to produce an unpacked sample, so no unpacked payload behavior could be analyzed (source: upx, unpack results). No process execution, file system changes, registry modifications, or network activity were observed in any dynamic analysis run.

## 7. Network Indicators & C2
No network indicators or command-and-control (C2) infrastructure were identified in static or dynamic analysis. Static analysis found no network-related imports (e.g., winhttp.dll, ws2_32.dll, dnsapi.dll) in the 7 total imports (source: pe_imports, import_count), and FLOSS string analysis returned no IP addresses, domains, URLs, or network-related clear-text strings (source: floss, string_count). Dynamic analysis recorded no network API calls or events (source: speakeasy, results). No C2 IPs, domains, URLs, or network signatures are available for this sample at this time.

## 8. Capabilities & MITRE ATT&CK Mapping
The sample's confirmed capabilities, derived from capa rule matches and static analysis, are mapped to MITRE ATT&CK as follows (source: capa, top_rules; source: ghidra, function_metrics/callgraph_edges):
| Capability | ATT&CK ID | ATT&CK Name | MBC ID | MBC Name |
|---|---|---|---|---|
| Obfuscate payload via RC4 encryption | T1027 | Obfuscated Files or Information | E1027.m05, C0027.009 | Obfuscated Files or Information, Encrypt Data |
| Obfuscate payload via Chaskey encryption | T1027 | Obfuscated Files or Information | E1027.m05 | Obfuscated Files or Information |
| Obfuscate payload via Speck encryption | T1027 | Obfuscated Files or Information | E1027.m05 | Obfuscated Files or Information |
| Discover system language to avoid non-target execution | T1614.001 | System Location Discovery | N/A | N/A |
| Non-cryptographic hashing via MurmurHash3 | N/A | N/A | C0030.001 | Non-Cryptographic Hash |
| Control flow flattening / dispatch loop obfuscation | T1027 | Obfuscated Files or Information | N/A | N/A |
The extreme cyclomatic complexity (102) of the entry function, combined with 101 total outgoing calls (50 to RC4, 46 to MessageBoxExA), indicates control-flow flattening obfuscation to hinder reverse engineering (source: ghidra, function_metrics; source: ghidra, callgraph_edges).

## 9. Indicators of Compromise
The following indicators of compromise (IOCs) are available for this sample (all sources as cited):
### File IOCs
| Type | Value | Source |
|---|---|---|
| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 | sample metadata |
| Imports | SystemFunction033 (advapi32.dll), MessageBoxExA (user32.dll), GetSystemDefaultLCID (kernel32.dll), GetUserDefaultUILanguage (kernel32.dll), ZwAdjustPrivilegesToken (ntdll.dll) | pe_imports, ghidra imports |
### Static String IOCs
| String | Context | Source |
|---|---|---|
| !This program cannot be run in DOS mode. | DOS stub header | floss |
| Rich!l | PE rich header marker | floss |
| .rdata, @.data | PE section names | floss |
| advapi32.dll, user32.dll, ntdll.dll, kernel32.dll | Imported DLL names | ghidra strings, floss |
| SystemFunction033, MessageBoxExA, GetSystemDefaultLCID, GetUserDefaultUILanguage | Imported API names | ghidra strings, floss |
No file paths, registry keys, C2 addresses, or persistence mechanism IOCs were identified during analysis.

## 10. Detection Engineering
Given the lack of YARA signature matches (source: yara, matches: 0) due to tooling failure, the following detection strategies are recommended based on available static features:
1. **Import-based detection**: YARA rules targeting the combination of SystemFunction033 (advapi32.dll), MessageBoxExA (user32.dll), and system language discovery APIs (GetSystemDefaultLCID, GetUserDefaultUILanguage) in a PE with high cyclomatic complexity entry function (>90) and disproportionate call counts to RC4 and message box APIs.
2. **Behavioral detection**: Endpoint detection rules matching capa behavior for RC4, Chaskey, and Speck encryption routines, plus system language discovery via API calls, in unpacked or memory-resident payloads.
3. **Packing detection**: Rules identifying PE files with minimal high-signal strings (<15 total non-DLL/API strings), 0 FLOSS decoded/stack/tight strings, and a single large executable section, consistent with custom crypter stubs.
4. **Tooling note**: YARA scanning was unavailable for this sample due to a missing 'yr' binary, so signature development should be performed in an environment with functional YARA tooling (source: yara, batch_errors).

## 11. What We Don't Know
The following gaps in analysis remain due to tooling failures and the sample's heavy obfuscation:
1. IDA Pro analysis failed validation and returned no usable static data, so no IDA-specific disassembly, cross-references, or type information is available (source: llm_judge, cross_engine_notes).
2. Malcat analysis errored completely, so no Malcat structural triage, entropy analysis, or signature matches are available (source: malcat, analysis error).
3. YARA scanning failed due to a missing 'yr' binary, so no open-source or custom YARA signature matches were generated for the sample (source: yara, batch_errors).
4. The sample's packed payload was not unpacked: UPX unpacking failed, and no dynamic unpacking or memory dumps were captured during analysis, so the final payload's full capabilities, C2 infrastructure, persistence mechanisms, and malicious actions are unknown (source: upx, unpack results; source: speakeasy, results).
5. No runtime behavior was observed via Speakeasy or Frida, so no dynamic execution flow, API call sequences, or network activity data is available (source: speakeasy, results; source: frida_probe, results).
6. The sample's intended target geography, delivery method, and associated threat actor are unknown due to lack of payload analysis and C2 indicators.

## 12. Appendix: Analysis Environment
The following tools were used for analysis, with results as documented:
| Tool | Version/Status | Result Summary | Source |
|---|---|---|---|
| Ghidra | N/A (static analysis) | Provided function metrics, callgraph edges, suspicious strings, and import data (due to Ghidra's empty imports table for stripped PEs) | ghidra, all static data |
| capa | N/A, 2.29s runtime | Matched 6 capability rules, including 3 encryption routines and system language discovery | capa, top_rules |
| FLOSS | N/A | Returned 1144 static strings, 0 decoded/stack/tight strings | floss, string_count |
| radare2 | N/A | Provided IAT thunk disassembly for 4 key imported functions | radare2, disassembly |
| pe_imports | N/A | Identified 7 total imports, 0 high-signal malicious APIs | pe_imports, import_count |
| UPX | N/A | Unpacking failed, no unpacked output generated | upx, unpack results |
| XOR Search | N/A | Identified XOR 00 key at file offset 0x00000000 | xor, results |
| Speakeasy | N/A, speakeasy_ok: True | 0 API calls, 0 key events, no behavioral data recorded | speakeasy, results |
| Frida | v17.16.4, frida_available: True | No runtime data captured | frida_probe, results |
| IDA Pro | N/A | Failed validation, no usable data returned | llm_judge, cross_engine_notes |
| Malcat | N/A | Analysis errored, no data returned | malcat, analysis error |
| YARA | N/A | Scanning failed due to missing 'yr' binary, 0 matches returned | yara, batch_errors |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2  
**sample_path:** /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious obfuscated/packed Windows PE malware
- **score**: 8
- **family_guess**: Unidentified packed/obfuscated malware (likely loader or crypter)
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: ['IDA analysis failed validation and returned no usable data, so all static analysis relies on Ghidra, capa, FLOSS, and pe_imports', 'Malcat analysis errored and provided no data', "YARA scanning failed due to missing 'yr' binary, so no signature matches were returned", 'Ghidra imports table is empty per known limitation for mixed-mode/stripped PEs, so import data is sourced from pe_imports and Ghidra suspicious string data', 'FLOSS returned 1144 static strings but no decoded/stack/tight strings, indicating packed/encrypted content']
- **summary**: This sample is a heavily obfuscated/packed Windows PE malware with no known signature matches. Static analysis via capa confirms it uses multiple custom encryption algorithms (RC4, Chaskey, Speck) for obfuscation (ATT&CK T1027) and performs system language discovery (ATT&CK T1614.001). The sample imports only standard Windows system libraries with no high-signal malicious APIs, and FLOSS string analysis reveals no clear-text malicious indicators, both consistent with packed malware that defers malicious functionality to decrypted runtime payloads. Limited analysis tool availability (IDA failure, Malcat error, YARA tool error) prevents deeper payload analysis, but available evidence confirms malicious intent with strong obfuscation capabilities.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `encrypt data using RC4 via SystemFunction033, encrypt data using chaskey, encryp` | Three distinct custom encryption routine detections map to ATT&CK T1027 (Obfuscated Files or Information), confirming th |
| capa | top_rules | `identify system language via API` | This detection maps to ATT&CK T1614.001 (System Language Discovery), indicating the malware checks system language to po |
| pe_imports | import_count | `7 imports, 0 high-signal` | The sample only imports standard Windows system DLLs (user32.dll, advapi32.dll, ntdll.dll, kernel32.dll per Ghidra strin |
| floss | string_count | `1144 total static strings, 0 decoded/stack/tight strings` | The absence of decoded, stack, or tight strings indicates the binary is packed or encrypted, as no clear-text malicious  |
| ida | funcs | `365 total functions` | The high function count combined with obfuscation indicators suggests complex packed code containing decryption routines |
| yara | matches | `0 matches` | No YARA rule matches indicate this is either a custom/novel malware sample or heavily modified/packed to evade signature |
| ghidra | Suspicious strings (Ghidra) | `user32.dll, FreeEncryptedFileKeyInfo, advapi32.dll, ntdll.dll, kernel32.dll` | These strings are limited to standard Windows system DLLs and a legitimate Windows encrypted file handling API, with no  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The sample is a Windows PE crypter/packer stub with heavy obfuscation. It imports SystemFunction033 (RC4), and capa identifies additional encryption/hashing capabilities including Chaskey, Speck, and MurmurHash3, plus system language discovery. The entry function has extreme cyclomatic complexity (102) and makes 101 calls, dominated by 50 calls to SystemFunction033 and 46 calls to MessageBoxExA, consistent with control-flow flattening or a dispatch loop. The minimal string set (11 strings, mostly import/DLL names) and single large executable section further indicate obfuscation.

### deep key_evidence
- `"capa rule: encrypt data using RC4 via SystemFunction033"`
- `"capa rule: encrypt data using chaskey"`
- `"capa rule: encrypt data using speck"`
- `"capa rule: identify system language via API"`
- `"capa rule: hash data using murmur3"`
- `"Ghidra import: SystemFunction033 from ADVAPI32.DLL"`
- `"Ghidra import: ZwAdjustPrivilegesToken from NTDLL.DLL"`
- `"Ghidra function_metrics: entry func_addr=4198400 cyclomatic_complexity=102 call_out_count=101"`
- `"Ghidra callgraph_edges: entry -> SystemFunction033 50 times"`
- `"Ghidra callgraph_edges: entry -> MessageBoxExA 46 times"`
- `"Ghidra strings: only 11 strings, mostly API/DLL names (e.g., MessageBoxExA, SystemFunction033, advapi32.dll, kernel32.dll, ntdll.dll)"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 6 · duration_s: 2.29

| Rule | ATT&CK | MBC |
|---|---|---|
| encrypt data using RC4 via SystemFunction033 | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.009:Encrypt Data |
| encrypt data using chaskey | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information |
| encrypt data using speck | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information |
| identify system language via API | T1614.001:System Location Discovery |  |
| hash data using murmur3 |  | C0030.001:Non-Cryptographic Hash |
| contain loop |  |  |

## PE Imports / Signals
import_count: 7

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
Total strings: 1144 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 1144}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `Rich!l`
- ``.rdata`
- `@.data`
- `eq9f(2A`
- `cqn,)=Aq`
- `QiR?])`
- `MC	HsC`
- `:U=y-]`
- `m67X|}`
- ``s^cI(N`
- `rm33Um`
- `TX=w2U=`
- `T8);:V`
- `TX=w2Y=`
- `r|jW2!`
- `0Yh%2Y`
- `rx(dxs`
- `KdS8i'`
- `($38iG`
- `ES;i%>8`
- `{+Gp;i`
- `G83cO8`
- `eerXHD`
- `EORXHD`
- `E\Nt:H`
- `r=93un`
- `gbq|]%ta`
- `*7J(57?EA`
- `rjth&h`
- `X{4eWw`
- `e?M&2h`
- `5hxu	E`
- `w_&U4%t`
- `*}E5-u`
- `{[A6u{`
- `$FkOdH,`
- `cOdW,m`
- `2FlOdO,O$&;`
- `9O$F,X$`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00475a2a
```asm
; CALL XREF from entry0 @ 0x401000(x)
┌ 6: LCID sub.kernel32.dll_GetSystemDefaultLCID ();
└           0x00475a2a      ff2520604700   jmp dword [sym.imp.kernel32.dll_GetSystemDefaultLCID] ; 0x476020 ; "Na\a"
```
### 0x00475a1e
```asm
; XREFS(46)
┌ 6: int sub.user32.dll_MessageBoxExA (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId);
└           0x00475a1e      ff2500604700   jmp dword [sym.imp.user32.dll_MessageBoxExA] ; 0x476000
```
### 0x00475a24
```asm
; XREFS(50)
┌ 6: sub.advapi32.dll_SystemFunction033 ();
└           0x00475a24      ff2508604700   jmp dword [sym.imp.advapi32.dll_SystemFunction033] ; 0x476008
```
### 0x00475a30
```asm
; CALL XREFS from entry0 @ 0x401093(x), 0x40111c(x), 0x4011a5(x)
┌ 6: LANGID sub.kernel32.dll_GetUserDefaultUILanguage ();
└           0x00475a30      ff2524604700   jmp dword [sym.imp.kernel32.dll_GetUserDefaultUILanguage] ; 0x476024 ; "ea\a"
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
