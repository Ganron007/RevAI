## 1. Executive Summary

This sample is confirmed malicious with a score of 85, classified as a UPX-packed generic malware sample likely acting as a loader or dropper for a second-stage payload (source: llm_judge, verdict, verdict: Malicious, score: 85, family_guess: UPX-packed generic malware (likely loader/dropper for second-stage payload)). Static analysis confirms UPX packing via capa rule `packed with UPX (ATT&CK T1027.002, MBC F0001.008)` (source: capa, top_rules, packed with UPX (ATT&CK T1027.002, MBC F0001.008)), with anomalously low function and string counts consistent with packed code: Ghidra identifies only 2 total functions and 12 total static strings (source: ghidra, funcs, Total function count = 2; source: ghidra, strings, Total string count = 12). High-signal imports resolved via pe_imports include LoadLibraryA, GetProcAddress, VirtualProtect, and VirtualAlloc, which are strongly associated with dynamic API resolution and memory manipulation for process injection (source: pe_imports, signals, High-signal imports: LoadLibrary (T1129), GetProcAddress (T1129), VirtualProtect (T1055), VirtualAlloc (T1055)). FLOSS string extraction identified fragments including `s HTTP/1.1` and `* ]\\8`, indicating the unpacked payload likely contains network communication functionality (source: capa, strings, Sampled strings include obfuscated payloads and fragments 'm HTTP/1.1' and '-url#c'; source: FLOSS, high-signal, * ]\\8, s HTTP/1.1). Tooling gaps limited analysis: IDA SQL, Malcat, and YARA scanning failed due to missing binaries, and UPX unpacking was unsuccessful, so no unpacked payload or runtime behavior was observed (source: llm_judge, cross_engine_notes; source: upx unpack, upx_ok: False, is_packed: False, returncode: None, unpacked_path: ; source: Speakeasy dynamic, api_calls: 0, key_events: 0; source: Frida Probe, frida_available: True, version: 17.16.4, no activity recorded).

## 2. Sample Metadata

| Field | Value |
|-------|-------|
| SHA256 | 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc |
| Sample Path | /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 85 |
| Family Guess | UPX-packed generic malware (likely loader/dropper for second-stage payload) |
| Agreement | llm_v1_disagree |
| Analysis Source | llm_judge (model: step-3.7-flash) |

Cross-engine analysis notes: IDA SQL and Malcat analysis failed due to missing tooling (idasql binary not found, malcat.mcp.py missing), so all static analysis evidence is sourced from Ghidra, capa, pe_imports, and FLOSS. Ghidra's empty imports table is a documented limitation for packed/stripped samples, and is superseded by pe_imports which successfully resolved 10 functional imports including 4 high-signal malicious APIs. YARA scanning failed due to a missing 'yr' binary, so no YARA rule matches were obtained and no YARA-based family identification was possible (source: llm_judge, cross_engine_notes).

## 3. File Layout & Structural Analysis

The sample is a valid PE format file confirmed to be UPX-packed via capa analysis (source: capa, top_rules, packed with UPX (ATT&CK T1027.002, MBC F0001.008)). .NET analysis returned `is_dotnet: false`, with no .NET metadata or assemblies observed (source: .NET Analysis, is_dotnet: false (not observed)). Ghidra static analysis identified an extremely low function count consistent with packing: 2 total functions, with an entry point at 0x004383280 and a single additional function `FUN_0042b818` at 0x004372504 (source: ghidra, funcs, Total function count = 2). Static string counts are also anomalously low for a functional PE: Ghidra resolved only 12 total static strings (source: ghidra, strings, Total string count = 12), with no meaningful decoded strings beyond import and module names identified.

Import analysis via pe_imports resolved 10 total functional imports, including high-signal APIs for malicious behavior (source: pe_imports, import_count: 10). FLOSS string extraction recovered 2050 total strings, all categorized as static strings, with no decoded, stack, tight, or language strings identified (source: FLOSS strings, Total strings: 2050, per_category: {"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2050}). An UPX unpack attempt was performed but failed: `upx_ok: False`, `is_packed: False`, `returncode: None`, and no unpacked output path was generated (source: upx unpack, upx_ok: False, is_packed: False, returncode: None, unpacked_path: ). XOR search identified a XOR 00 position at 0x00000000, with adjacent bytes matching the standard PE DOS header stub (source: XOR Search, Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r).

## 4. Malcat Triage Summary

Malcat analysis failed entirely due to missing tooling: the analysis returned the error `MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory` (source: Malcat Structured Analysis, Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory). No Malcat triage data, string analysis, or structural data is available for this sample.

## 5. Static Code Analysis

### capa Capability Rules

capa analysis matched 3 total rules, with a runtime duration of 3.03 seconds (source: capa Capability Rules, engine: capa · Total rules: 3 · duration_s: 3.03):

| Rule | ATT&CK | MBC |
|------|--------|-----|
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

### Full Import Address Table (IAT)

pe_imports resolved 10 total functional imports, with 4 high-signal malicious APIs (source: pe_imports, PE Imports / Signals, import_count: 10):

| Label | API Match | ATT&CK |
|-------|-----------|--------|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |
| free_memory | VirtualFree |  |
| exit_process | ExitProcess |  |
| string_to_int | atoi |  |
| string_format | wsprintfA |  |
| oleaut32_ordinal | OLEAUT32 Ordinal_200 |  |
| ws2_32_ordinal | WS2_32 Ordinal_116 |  |

### Ghidra Function Metrics

Ghidra identified only 2 total functions, with no complex control flow or high-level logic visible due to UPX packing (source: ghidra, funcs, Total function count = 2; source: deep_dive_agentic, key_evidence, Ghidra funcs: 2 functions (entry at 4383280, FUN_0042b818 at 4372504)). No meaningful decoded strings beyond import and module names were found in Ghidra string analysis (source: deep_dive_agentic, key_evidence, No meaningful decoded strings beyond import/module names in Ghidra strings query). The entry point (EP) for the sample is located at 0x004383280; no decompress disassembly is available for the UPX stub or entry point due to the failed unpack attempt (source: ghidra, funcs, entry at 4383280; source: upx unpack, upx_ok: False).

### High-Signal Strings

FLOSS extracted 2050 static strings, with 2 high-signal fragments indicating network functionality in the unpacked payload (source: FLOSS, High-signal FLOSS):
- `* ]\\8`
- `s HTTP/1.1`

A sample of additional static strings extracted by FLOSS includes:
`!This program cannot be run in DOS mode.`, `%6w*iA`, `h8U^L&`, `cR>#4jX(C`, `59D;Fw`, `.SW1zTE`, `Cb|cn+`, ``ud2KTcxwc`, `]pg&*+`, `/Qmlv%uwjbwdh%fdkkjq%g`%wpk%`, `AJV%hja`+`, `9'Wlfm?`, `w`}nw+`, `u34v43`, `asw=((`, `:cd616rv7Z6`, ``q	Sfs`, `RVDV`k`, `x5y<{i`, `g*QQ!U`, `<!65{+`, `PN8f<#`, `BPQ`huUdq`, `Rwlq`Uwjf`v`, `V-`uFijv`pj`, `_x5`Qm`, `}TW$U+`, `5Z9op\`, `[{Zcalshd`, `Mjjn@}`, `N@WK@I`, `HVSFWQ`, `/IjdaIl`, `cftcrk`, `10,fnn3igpin`, `RpmaCffpgO`, `loglvTcpkc`ng`, `klGzga`, `Amr{Dk` (source: FLOSS, FLOSS sample).

### UPX Unpack Output

UPX unpack attempt failed with no stdout output, no unpacked path generated, and a null return code (source: upx unpack, upx_ok: False, is_packed: False, returncode: None, unpacked_path: ). No decompress disassembly is available for the entry point or UPX stub due to the failed unpack.

## 6. Behavioral & Dynamic Analysis

No dynamic runtime behavior was observed during analysis. Speakeasy dynamic analysis executed successfully (`speakeasy_ok: True`) but recorded 0 API calls and 0 key events, with no duration or activity logged (source: Speakeasy (dynamic), speakeasy_ok: True, api_calls: 0, key_events: 0, duration_s: None, not observed: no API calls/events recorded — do not invent runtime behavior). Frida Probe confirmed Frida is available (version 17.16.4) but no instrumentation or runtime activity was captured (source: Frida Probe, frida_available: True, version: 17.16.4). The failed UPX unpack attempt also prevented dynamic analysis of the unpacked second-stage payload (source: upx unpack, upx_ok: False, is_packed: False, returncode: None, unpacked_path: ).

## 7. Network Indicators & C2

No concrete C2 infrastructure (IP addresses, domains, URLs) was identified in static analysis, as all static strings are obfuscated or compressed by UPX packing (source: FLOSS strings, Total strings: 2050, per_category: {"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2050}). Indirect indicators of network functionality were observed: FLOSS extracted the fragment `s HTTP/1.1`, which indicates the unpacked payload likely implements HTTP-based network communication (source: FLOSS, high-signal, s HTTP/1.1; source: capa, strings, Sampled strings include obfuscated payloads and fragments 'm HTTP/1.1' and '-url#c'). The presence of the WS2_32 Ordinal_116 import further indicates potential Winsock network functionality in the unpacked payload (source: pe_imports, PE Imports / Signals, ws2_32_ordinal | WS2_32 Ordinal_116 | ; source: ghidra, imports, Ghidra imports: LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess, atoi, wsprintfA, OLEAUT32 Ordinal_200, WS2_32 Ordinal_116). All network indicators are only visible after successful UPX unpacking, which was not achieved in this analysis.

## 8. Capabilities & MITRE ATT&CK Mapping

All mapped capabilities are derived from static analysis evidence, with no dynamic behavior observed:

| Capability | Evidence Source | ATT&CK Technique | MBC |
|------------|-----------------|------------------|-----|
| UPX Software Packing | capa, top_rules, packed with UPX (ATT&CK T1027.002, MBC F0001.008) | T1027.002: Obfuscated Files or Information | F0001.008: Software Packing |
| Dynamic API Resolution | pe_imports, signals, High-signal imports: LoadLibrary (T1129), GetProcAddress (T1129) | T1129 |  |
| Memory Protection Modification | pe_imports, signals, High-signal imports: VirtualProtect (T1055) | T1055: Process Injection |  |
| Executable Memory Allocation | pe_imports, signals, High-signal imports: VirtualAlloc (T1055) | T1055: Process Injection |  |
| Potential HTTP Network Communication | FLOSS, high-signal, s HTTP/1.1; pe_imports, ws2_32_ordinal | T1071: Application Layer Protocol |  |
| Process Termination | pe_imports, exit_process |  |  |
| String Formatting | pe_imports, string_format |  |  |
| Integer String Conversion | pe_imports, string_to_int |  |  |

Additionally, capa matched a `contain loop` rule with no assigned ATT&CK or MBC mapping (source: capa, top_rules, contain loop).

## 9. Indicators of Compromise

### File-Based IOCs
- **SHA256**: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc (source: sample metadata, sha256: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc)
- **UPX Packer Signature**: Confirmed via capa rule `packed with UPX` (source: capa, top_rules, packed with UPX (ATT&CK T1027.002, MBC F0001.008))

### Import-Based IOCs
The following 10 imports are present in the sample, with 4 high-signal malicious APIs (source: pe_imports, PE Imports / Signals, import_count: 10):
1. LoadLibraryA (T1129)
2. GetProcAddress (T1129)
3. VirtualProtect (T1055)
4. VirtualAlloc (T1055)
5. VirtualFree
6. ExitProcess
7. atoi
8. wsprintfA
9. OLEAUT32 Ordinal_200
10. WS2_32 Ordinal_116

### String-Based IOCs
High-signal FLOSS static strings (source: FLOSS, High-signal FLOSS):
- `* ]\\8`
- `s HTTP/1.1`

No file paths, registry keys, or hardcoded C2 IPs/domains were identified in static analysis, as all non-import strings are obfuscated by UPX packing.

## 10. Detection Engineering

### YARA Rules
YARA scanning failed due to missing `yr` binary, so no sample-specific YARA rule matches were obtained (source: Generated YARA Meta, rule_count: 0, matches: []). The full YARA execution error log is below:
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
A generic detection YARA rule can be constructed to flag UPX-packed PE files with the observed import set (LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, WS2_32, OLEAUT32) and anomalously low function (<20) and static string (<20) counts.

### Static Detection Logic
Alert on PE files meeting the following criteria, which are highly indicative of packed malware:
1. UPX packing signature confirmed via capa or binary header analysis (source: capa, top_rules, packed with UPX (ATT&CK T1027.002, MBC F0001.008))
2. Imports the combination of LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, and WS2_32 (source: pe_imports, signals, High-signal imports: LoadLibrary (T1129), GetProcAddress (T1129), VirtualProtect (T1055), VirtualAlloc (T1055))
3. Total function count <20 and total static string count <20 (source: ghidra, funcs, Total function count = 2; source: ghidra, strings, Total string count = 12)

### Dynamic Detection Logic
1. **Memory Execution Alerting**: Monitor for processes that call VirtualProtect to modify memory regions to executable (RX) permissions, followed by execution of code in those regions, a common pattern for UPX unpacking and process injection (source: pe_imports, signals, change_memory_protection | VirtualProtect | T1055).
2. **Network Anomaly Detection**: Alert on HTTP requests from processes that dynamically resolve WS2_32 or OLEAUT32 APIs via GetProcAddress, as this matches the observed import pattern and network string fragments (source: FLOSS, high-signal, s HTTP/1.1; source: pe_imports, ws2_32_ordinal).
3. **Unpacked Payload Analysis**: Once UPX unpacking is successful, generate YARA rules for the unpacked second-stage payload to enable downstream detection of the final malware component.

## 11. What We Don't Know

1. **Unpacked Payload Functionality**: UPX unpacking failed, so the capabilities, purpose, and malware family of the embedded second-stage payload are unknown (source: upx unpack, upx_ok: False, is_packed: False, returncode: None, unpacked_path: ).
2. **C2 Infrastructure**: No static C2 IPs, domains, or URLs were identified, as all network-related strings are obfuscated in the packed sample (source: FLOSS strings, Total strings: 2050, per_category: {"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2050}; source: 7. Network Indicators & C2).
3. **Final Malware Family**: No YARA matches or high-level static indicators were found to confirm the final malware family, only that it is a UPX-packed loader/dropper (source: llm_judge, family_guess: UPX-packed generic malware (likely loader/dropper for second-stage payload); source: Generated YARA Meta, rule_count: 0, matches: []).
4. **Runtime Behavior**: No dynamic behavior was observed via Speakeasy or Frida, so actual execution flow, payload dropping, or network activity is unknown (source: Speakeasy (dynamic), api_calls: 0, key_events: 0; source: Frida Probe, frida_available: True, version: 17.16.4, no activity recorded).
5. **Deep Static Analysis**: IDA SQL and Malcat analysis failed due to missing tooling, so no additional function-level disassembly, cross-reference, or triage data is available from those tools (source: llm_judge, cross_engine_notes: IDA SQL and Malcat analysis failed due to missing tooling (idasql binary not found, malcat.mcp.py missing)).

## 12. Appendix: Analysis Environment

| Tool | Status | Output/Notes |
|------|--------|-------------|
| Ghidra | Successful | 2 functions, 12 static strings, entry point 0x004383280 |
| capa | Successful | 3 rules matched, 3.03s runtime |
| pe_imports | Successful | 10 total imports, 4 high-signal malicious APIs |
| FLOSS | Successful | 2050 total static strings, 2 high-signal network fragments |
| UPX | Failed | Unpack attempt returned null return code, no unpacked output |
| Speakeasy | Successful (no activity) | 0 API calls, 0 key events, no runtime behavior observed |
| Frida Probe | Successful (no activity) | Frida v17.16.4 available, no instrumentation captured |
| IDA SQL | Failed | Missing `idasql` binary, no analysis performed |
| Malcat | Failed | Missing `/opt/malcat/bin/malcat.mcp.py`, no analysis performed |
| YARA | Failed | Missing `yr` binary, no rule matches obtained |

Sample analysis details:
- SHA256: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc
- Sample Path: /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir
- Project Name: incoming
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc  
**sample_path:** /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 85
- **family_guess**: UPX-packed generic malware (likely loader/dropper for second-stage payload)
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA SQL and Malcat analysis failed due to missing tooling (idasql binary not found, malcat.mcp.py missing), so all static analysis evidence is sourced from Ghidra, capa, pe_imports, and FLOSS. Ghidra's empty imports table is a documented limitation for packed/stripped samples, and is superseded by pe_imports which successfully resolved 10 functional imports including 4 high-signal malicious APIs. YARA scanning failed due to a missing 'yr' binary, so no YARA rule matches were obtained and no YARA-based family identification was possible.
- **summary**: This sample is confirmed to be UPX-packed malicious malware, with a high likelihood of being a loader or dropper for a second-stage payload. Static analysis shows extremely low function and string counts consistent with packing, high-signal imports for runtime API resolution and memory manipulation (consistent with process injection), and FLOSS strings indicating potential network functionality in the unpacked payload. Missing tooling for IDA, Malcat, and YARA limited deeper analysis, but existing evidence is sufficient for a high-confidence malicious verdict.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with UPX (ATT&CK T1027.002, MBC F0001.008)` | Confirms the sample is compressed using UPX, a widely abused packer for obfuscating malware to evade static detection, w |
| pe_imports | signals | `High-signal imports: LoadLibrary (T1129), GetProcAddress (T1129), VirtualProtect` | These APIs are strongly associated with malicious packed samples: LoadLibrary/GetProcAddress enable runtime dynamic reso |
| ghidra | funcs | `Total function count = 2` | A functional legitimate PE would have dozens to thousands of functions; this extremely low count is consistent with pack |
| ghidra | strings | `Total string count = 12` | Legitimate PEs typically have hundreds to thousands of static strings; this low count is consistent with UPX packing com |
| capa | strings | `Sampled strings include obfuscated payloads and fragments 'm HTTP/1.1' and '-url` | These fragments indicate the unpacked payload likely has network communication functionality, a common feature of malwar |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 70
- **summary**: The sample is a small packed PE (capa: packed with UPX) with only 2 functions and 10 imports in Ghidra. It imports LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess, atoi, wsprintfA, plus OLEAUT32 and WS2_32 ordinals, indicating dynamic API resolution, memory protection changes, and likely network or shellcode execution. No high-level strings or clear payload indicators were found in static strings, consistent with UPX packing and/or encrypted payload.

### deep key_evidence
- `"capa top rule: packed with UPX (T1027.002 / F0001.008)"`
- `"Ghidra funcs: 2 functions (entry at 4383280, FUN_0042b818 at 4372504)"`
- `"Ghidra imports: LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess, atoi, wsprintfA, OLEAUT32 Ordinal_200, WS2_32 Ordinal_116"`
- `"PE import signals: load_library, get_proc_address, change_memory_protection, allocate_memory"`
- `"No meaningful decoded strings beyond import/module names in Ghidra strings query"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 3 · duration_s: 3.03

| Rule | ATT&CK | MBC |
|---|---|---|
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

## PE Imports / Signals
import_count: 10

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

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
Total strings: 2050 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2050}`

### High-signal FLOSS
- `*	]\\8`
- `s HTTP/1.1`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `%6w*iA`
- `h8U^L&`
- `cR>#4jX(C`
- `59D;Fw`
- `.SW1zTE`
- `Cb|cn+`
- ``ud2KTcxwc`
- `]pg&*+`
- `/Qmlv%uwjbwdh%fdkkjq%g`%wpk%`
- `AJV%hja`+`
- `9'Wlfm?`
- `w`}nw+`
- `u34v43`
- `asw=((`
- `:cd616rv7Z6`
- ``q	Sfs`
- `RVDV`k`
- `*	]\\8`
- `x5y<{i`
- `g*QQ!U`
- `<!65{+`
- `PN8f<#`
- `BPQ`huUdq`
- `Rwlq`Uwjf`v`
- `V-`uFijv`pj`
- `_x5`Qm`
- `}TW$U+`
- `5Z9op\`
- `[{Zcalshd`
- `Mjjn@}`
- `N@WK@I`
- `HVSFWQ`
- `/IjdaIl`
- `cftcrk`
- `10,fnn3igpin`
- `RpmaCffpgO`
- `loglvTcpkc`ng`
- `klGzga`
- `Amr{Dk`

## .NET Analysis
- is_dotnet: false (not observed)

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
