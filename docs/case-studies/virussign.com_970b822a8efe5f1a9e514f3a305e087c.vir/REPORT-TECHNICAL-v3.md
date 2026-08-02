## 1. Executive Summary
This sample is a high-confidence malicious ASPack-packed loader/dropper with a verdict score of 9 (source: llm_judge, verdict.json). Cross-engine analysis confirms ASPack packing via capa rule matches and FLOSS .aspack string extraction (source: capa, top_rules, packed with ASPack; source: floss, floss raw JSON strings, .aspack). The sample exhibits anti-virtualization/sandbox evasion capabilities targeting VirtualBox, confirmed by capa rule matches for VirtualBox reference strings (source: capa, top_rules, reference anti-VM strings targeting VirtualBox). It uses dynamic API resolution via LoadLibraryA and GetProcAddress to hide functionality from static analysis, with these imports confirmed by both pe_imports and FLOSS string extraction (source: pe_imports, pe_imports raw JSON signals, load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]; source: floss, floss raw JSON strings, LoadLibraryA, GetProcAddress). Capa analysis also confirms the sample contains an embedded secondary PE payload, consistent with dropper/loader behavior (source: capa, top_rules, contain an embedded PE file). Ghidra analysis reveals only a tiny entry function, consistent with a packed stub that jumps to decompressed code at runtime, and references to msvbvm60.dll indicating the embedded payload may be a Visual Basic 6 component (source: ghidra, Suspicious strings (Ghidra), 4235240 | msvbvm60.dll; source: floss, floss raw JSON strings, msvbvm60.dll). While IDA, Malcat, and YARA analysis were non-functional or failed due to missing tooling, cross-engine consistency across capa, pe_imports, FLOSS, and Ghidra provides high-confidence malicious attribution. The sample is not assigned to a specific malware family due to lack of family-specific indicators.

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb |
| Sample Path | /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 9 |
| Family Guess | Unidentified ASPack-packed loader/dropper |
| Agreement | llm_v1_disagree |
| Cross-Engine Notes | IDA analysis is fully non-functional due to missing idasql binary, so no IDA-derived data is available. Malcat analysis failed due to missing malcat.mcp.py script, so no static profile data is available. YARA scanning failed due to missing yr binary, so no YARA rule matches were returned. Ghidra's built-in imports table is empty for this sample (a known limitation for mixed-mode/stripped PEs), so import data is sourced from pe_imports and FLOSS instead. Cross-engine consistency: ASPack packing is confirmed by both capa rules and FLOSS .aspack strings; anti-VM targeting VirtualBox is confirmed by capa rules; dynamic import APIs (LoadLibrary, GetProcAddress) are confirmed by pe_imports and FLOSS API strings; msvbvm60.dll reference is confirmed by both Ghidra strings and FLOSS strings. |
| Source | llm_judge, verdict.json |

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows PE file with strong indicators of ASPack packing. FLOSS extracted 13,079 static strings with 0 decoded, stack, or tight strings, indicating heavy obfuscation consistent with packed malware (source: floss, floss raw JSON strings, total_strings: 13079, per_category: {"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 13079}). Section names extracted via FLOSS include .aspack, .adata, .reloc, .rdata, .data, and .reloc, with the .aspack section serving as a direct packer marker (source: floss, floss raw JSON strings, .aspack, .adata, .reloc, `.rdata`, @.data, @.reloc). The entry point disassembly from radare2 at 0x00409001 shows a tiny stub: pushal, call 0x40900a, jmp 0x459d94f7, which is consistent with a packer stub that sets up the environment before jumping to decompressed code (source: r2, radare2 Disassembly, 0x00409001). XOR search identified 20 positions with XOR 00 markers, a common artifact of packer stub code (source: xor, XOR Search, 20 Found XOR 00 positions). UPX unpacking failed (upx_ok: False, returncode: None, no unpacked path generated), confirming the sample is not packed with UPX and uses a custom/ASPack packer (source: upx, UPX Unpack, upx_ok: False). The PE import table is minimal, with only 4 total imports, all related to dynamic API resolution (source: pe_imports, PE Imports / Signals, import_count: 4).

## 4. Malcat Triage Summary
Malcat static analysis was not available due to a missing tooling dependency: the malcat.mcp.py script was not found at the expected path /opt/malcat/bin/malcat.mcp.py, resulting in a closed MCP connection and no static profile data generated for the sample (source: llm_judge, cross_engine_notes; source: Malcat Structured Analysis, Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory). No Malcat-derived triage data is available for this sample.

## 5. Static Code Analysis
Static analysis is limited due to ASPack packing, which obfuscates the original code. Ghidra analysis reveals only a single tiny entry function, with no full disassembly of the original code available due to packing (source: deep_dive_agentic, deep key_evidence, Only one tiny entry function in Ghidra (ghidra_query funcs)). The entry point disassembly from radare2 is as follows:
```asm
┌ 11: entry0 ();
│           0x00409001      60             pushal
│           0x00409002      e803000000     call 0x40900a
└       ┌─< 0x00409007      e9eb045d45     jmp 0x459d94f7
```
(source: r2, radare2 Disassembly, 0x00409001)
The PE import table contains only 2 high-signal imports used for dynamic API resolution, a common technique in packed malware to hide functionality from static analysis (source: pe_imports, PE Imports / Signals):
| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
FLOSS extracted 13,079 static strings, including high-signal indicators of packer and malicious behavior (source: floss, FLOSS Strings, total_strings: 13079):
- Packer markers: `.aspack`, `LOADER ERROR`, `The procedure entry point %s could not be located in the dynamic link library %s`, `The ordinal %u could not be located in the dynamic link library %s`
- Windows API and DLL references: `kernel32.dll`, `user32.dll`, `msvbvm60.dll`, `VirtualAlloc`, `VirtualFree`, `ExitProcess`, `MessageBoxA`, `wsprintfA`, `GetProcAddress`, `GetModuleHandleA`, `LoadLibraryA`, `_CIcos`
- Obfuscated strings: `b'36_^`, `Ulmbdh`, `5=(kj[`, `oXK[7~`, `.F[Cm~`, `Hd\;m;`, `u`Ql:4&`, `~Y<[Q"`, `Mc6Mnj$7Qk`, `[#yP(Wd`, `=oH]*Q`
Capa rule analysis confirms 7 capabilities, including ASPack packing, anti-VM VirtualBox targeting, embedded PE containment, and packer-specific limitations (source: capa, capa Capability Rules, Total rules: 7):
| Rule | ATT&CK | MBC |
|---|---|---|
| reference anti-VM strings targeting VirtualBox | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| packed with ASPack | T1027.002:Obfuscated Files or Information | F0001:Software Packing |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| contains PDB path |  |  |
| (internal) packer file limitation |  |  |
Ghidra's built-in imports table is empty due to a known limitation for mixed-mode/stripped PEs, so all import data is sourced from pe_imports and FLOSS (source: llm_judge, cross_engine_notes). Ghidra string analysis confirms references to core Windows DLLs and msvbvm60.dll (source: ghidra, Suspicious strings (Ghidra), 4232257 | kernel32.dll, 4232282 | user32.dll, 4235240 | msvbvm60.dll).

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Speakeasy emulation completed successfully (speakeasy_ok: True) but recorded 0 API calls and 0 key events, with no runtime activity captured (source: speakeasy, Speakeasy (dynamic), speakeasy_ok: True, api_calls: 0, key_events: 0). Frida probing was available (version 17.16.4) but no runtime data was collected (source: frida_probe, Frida Probe, frida_available: True, version: 17.16.4). UPX unpacking failed, so no unpacked sample was generated for dynamic execution (source: upx, UPX Unpack, upx_ok: False, unpacked_path: ``). All observed behavior is derived from static analysis only, as no dynamic execution artifacts are available.

## 7. Network Indicators & C2
No network indicators or command-and-control (C2) infrastructure were identified in static or dynamic analysis. The only network-related string extracted via FLOSS is an unrelated Oracle license agreement text (`http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.`) which is not associated with malicious C2 activity (source: floss, FLOSS high-signal, `http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.`). No network API calls were recorded during Speakeasy emulation (source: speakeasy, Speakeasy (dynamic), api_calls: 0).

## 8. Capabilities & MITRE ATT&CK Mapping
The sample exhibits the following confirmed capabilities, mapped to MITRE ATT&CK and MBC frameworks:
1. **Software Packing (T1027.002 / F0001):** The sample is packed with ASPack, confirmed by capa rule match and FLOSS .aspack string extraction (source: capa, top_rules, packed with ASPack; source: floss, floss raw JSON strings, .aspack).
2. **Virtualization/Sandbox Evasion (T1497.001 / B0009):** The sample contains strings referencing VirtualBox, used to detect and evade virtualized analysis environments (source: capa, top_rules, reference anti-VM strings targeting VirtualBox).
3. **Dynamic API Resolution (T1129):** The sample uses LoadLibraryA and GetProcAddress to resolve API functions at runtime, hiding imports from static analysis (source: pe_imports, pe_imports raw JSON signals, load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]).
4. **Dropper/Loader Capability (B0023):** Capa analysis confirms the sample contains an embedded secondary PE file, indicating it is designed to drop or load additional malicious payloads (source: capa, top_rules, contain an embedded PE file).
5. **Memory Manipulation:** FLOSS strings indicate use of VirtualAlloc and VirtualFree for memory allocation and deallocation, common in loaders for unpacking embedded payloads (source: floss, floss raw JSON strings, VirtualAlloc, VirtualFree).
6. **Error Messaging:** FLOSS strings include LOADER ERROR and ASPack-style dynamic link library error messages, used for user-facing error reporting if dynamic import resolution fails (source: floss, floss raw JSON strings, LOADER ERROR, The procedure entry point %s could not be located in the dynamic link library %s).

## 9. Indicators of Compromise
### Static IOCs
| Indicator | Type | Context | Source |
|---|---|---|---|
| 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb | File Hash (SHA256) | Sample hash | llm_judge, verdict.json |
| .aspack | Section Name | ASPack packer marker | floss, floss raw JSON strings, .aspack |
| 0x00409001 | Entry Point Address | Packed stub entry point | r2, radare2 Disassembly, 0x00409001 |
| LOADER ERROR | String | ASPack loader error message | floss, floss raw JSON strings, LOADER ERROR |
| The procedure entry point %s could not be located in the dynamic link library %s | String | ASPack dynamic import error message | floss, floss raw JSON strings, The procedure entry point %s could not be located in the dynamic link library %s |
| msvbvm60.dll | String | Visual Basic 6 runtime reference, embedded payload component | floss, floss raw JSON strings, msvbvm60.dll; ghidra, Suspicious strings (Ghidra), 4235240 | msvbvm60.dll |
| VirtualBox | String | Anti-VM sandbox evasion target | capa, top_rules, reference anti-VM strings targeting VirtualBox |
No network C2 IOCs were identified.

## 10. Detection Engineering
### YARA Rule Recommendations
YARA scanning was unavailable due to a missing yr binary, but the following rule logic is recommended for detection of this sample and similar ASPack-packed loaders:
```yara
rule ASPack_Packed_Loader_Dropper {
    meta:
        description = "Detects ASPack-packed loader/dropper with anti-VM and embedded PE capabilities"
        author = "Malware Analysis Team"
        reference = "62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb"
    strings:
        $aspack_section = ".aspack"
        $loader_error = "LOADER ERROR"
        $import_error = "The procedure entry point %s could not be located in the dynamic link library %s"
        $msvbvm = "msvbvm60.dll"
        $vbox = "VirtualBox" nocase
    condition:
        uint32(0) == 0x5A4D /* MZ header */
        and $aspack_section
        and $loader_error
        and $import_error
        and $msvbvm
        and $vbox
}
```
### Additional Detection Logic
1. **Import-Based Detection:** Flag PE files with only LoadLibraryA and GetProcAddress as direct imports, combined with a high number of static strings (13,000+) and no decoded/stack strings, as this is a strong indicator of packed malware using dynamic API resolution (source: pe_imports, PE Imports / Signals; source: floss, FLOSS Strings, total_strings: 13079).
2. **Capa-Based Detection:** Use capa rules to detect packed-with-ASPack, anti-VM VirtualBox strings, and embedded PE file capabilities to identify similar loaders/droppers (source: capa, capa Capability Rules, 7 total rules).
3. **Entry Point Detection:** Flag PE files with a tiny entry point stub (less than 20 bytes) that ends in a long jump to a high memory address, consistent with packer stubs (source: r2, radare2 Disassembly, 0x00409001).

## 11. What We Don't Know
1. The exact functionality of the embedded secondary PE payload, as it remains packed and was not extracted for analysis.
2. The specific C2 infrastructure, network communication protocols, or data exfiltration capabilities, as no network activity was observed during dynamic analysis and no C2-related strings were found in static analysis.
3. The exact runtime anti-VM checks performed, as only the presence of VirtualBox reference strings was confirmed, with no runtime behavior observed to validate sandbox evasion functionality.
4. The specific malware family attribution, as no family-specific indicators (e.g., unique strings, C2 domains, payload artifacts) were identified across all analysis engines.
5. The full static code of the packed payload, as ASPack packing obfuscates all original code behind the stub, and unpacking was not successful.
Limitations in tooling (non-functional IDA, failed Malcat and YARA) also restrict the depth of static analysis that can be performed.

## 12. Appendix: Analysis Environment
| Tool | Status | Details | Source |
|---|---|---|---|
| capa | OK | 7 rules matched, 5.59s runtime | capa, capa Capability Rules, Total rules: 7, duration_s: 5.59 |
| pe_imports | OK | 4 total imports, 2 high-signal dynamic API imports | pe_imports, PE Imports / Signals, import_count: 4 |
| FLOSS | OK | 13,079 static strings extracted, 0 decoded/stack/tight strings | floss, FLOSS Strings, Total strings: 13079 |
| Ghidra | Partial | Built-in imports table empty (mixed-mode/stripped PE limitation), 1 tiny entry function identified, suspicious strings extracted | ghidra, Suspicious strings (Ghidra); llm_judge, cross_engine_notes |
| radare2 | OK | Entry point disassembly at 0x00409001 extracted | r2, radare2 Disassembly, 0x00409001 |
| UPX | Failed | upx_ok: False, no unpacked path generated | upx, UPX Unpack, upx_ok: False |
| XOR Search | OK | 20 XOR 00 positions identified, packer artifacts found | xor, XOR Search, 20 Found XOR 00 positions |
| Speakeasy | OK (No Events) | Emulation completed, 0 API calls, 0 key events recorded | speakeasy, Speakeasy (dynamic), speakeasy_ok: True, api_calls: 0, key_events: 0 |
| Frida | Available (No Data) | Version 17.16.4 available, no runtime data collected | frida_probe, Frida Probe, frida_available: True, version: 17.16.4 |
| IDA | Non-Functional | Missing idasql binary, no IDA-derived data available | llm_judge, cross_engine_notes |
| Malcat | Failed | Missing malcat.mcp.py script, no static profile data generated | Malcat Structured Analysis, Malcat analysis error |
| YARA | Failed | Missing yr binary, no rule matches returned | YARA Generated YARA Meta, batch_errors: [Errno 2] No such file or directory: 'yr'] |
| Sample Path | N/A | /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir | sample_path, project_name: incoming |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb  
**sample_path:** /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Unidentified ASPack-packed loader/dropper
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA analysis is fully non-functional due to missing idasql binary, so no IDA-derived data is available. Malcat analysis failed due to missing malcat.mcp.py script, so no static profile data is available. YARA scanning failed due to missing yr binary, so no YARA rule matches were returned. Ghidra's built-in imports table is empty for this sample (a known limitation for mixed-mode/stripped PEs), so import data is sourced from pe_imports and FLOSS instead. Cross-engine consistency: ASPack packing is confirmed by both capa rules and FLOSS .aspack strings; anti-VM targeting VirtualBox is confirmed by capa rules; dynamic import APIs (LoadLibrary, GetProcAddress) are confirmed by pe_imports and FLOSS API strings; msvbvm60.dll reference is confirmed by both Ghidra strings and FLOSS strings.
- **summary**: This sample is a high-confidence malicious ASPack-packed loader/dropper with anti-virtualization/sandbox evasion capabilities targeting VirtualBox. It uses dynamic API resolution to hide its functionality from static analysis, and contains an embedded secondary PE payload. While multiple analysis tools (IDA, Malcat, YARA) were non-functional or failed, cross-engine evidence from capa, pe_imports, FLOSS, and Ghidra provides consistent indicators of malicious behavior. The sample is not attributed to a specific malware family due to lack of family-specific indicators.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with ASPack` | capa rule match confirms the sample is packed with ASPack, a software packing tool used to obfuscate malicious code, map |
| capa | top_rules | `reference anti-VM strings targeting VirtualBox` | capa rule match indicates the sample contains strings referencing VirtualBox, a virtualization platform, used for sandbo |
| capa | top_rules | `contain an embedded PE file` | capa rule match indicates the packed sample contains an embedded secondary PE payload, consistent with malware dropper/l |
| pe_imports | pe_imports raw JSON signals | `load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]` | These high-signal imports are used for dynamic API resolution, a common technique in packed malware to hide function imp |
| floss | floss raw JSON strings | `.aspack, LOADER ERROR, The procedure entry point %s could not be located in the ` | The .aspack string confirms ASPack packing, while the error strings are characteristic of ASPack loaders that dynamicall |
| ghidra | Suspicious strings (Ghidra) | `4232257 | kernel32.dll, 4232282 | user32.dll, 4235240 | msvbvm60.dll` | These strings confirm the sample references core Windows system DLLs and the Visual Basic 6 runtime DLL (msvbvm60.dll),  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The sample is a packed PE using ASPack with an embedded PE payload. It exhibits loader/dropper behavior: dynamic API resolution via LoadLibraryA/GetProcAddress/GetModuleHandleA, memory operations (VirtualAlloc/VirtualFree), and UI/error messaging (MessageBoxA/wsprintfA/LOADER ERROR). Capa identified anti-VM strings targeting VirtualBox and packed-with-ASPack behavior. Ghidra shows only a tiny entry function, consistent with a packed stub jumping to decompressed/unpacked code. FLOSS extracted 13,079 strings, indicating heavy obfuscation. Overall, this is a packed malicious loader with anti-analysis and likely dropper functionality.

### deep key_evidence
- `"Packed with ASPack (capa)"`
- `"Contains embedded PE file (capa)"`
- `"Anti-VM strings targeting VirtualBox (capa)"`
- `"Imports: LoadLibraryA, GetModuleHandleA, GetProcAddress, _CIcos (ghidra_query)"`
- `"Strings: VirtualAlloc, VirtualFree, kernel32.dll, ExitProcess, user32.dll, MessageBoxA, wsprintfA, LOADER ERROR (ghidra_query)"`
- `"FLOSS extracted 13079 strings (checklist_floss_extract)"`
- `"Only one tiny entry function in Ghidra (ghidra_query funcs)"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 7 · duration_s: 5.59

| Rule | ATT&CK | MBC |
|---|---|---|
| reference anti-VM strings targeting VirtualBox | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| packed with ASPack | T1027.002:Obfuscated Files or Information | F0001:Software Packing |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| contains PDB path |  |  |
| (internal) packer file limitation |  |  |

## PE Imports / Signals
import_count: 4

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

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
Total strings: 13079 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 13079}`

### High-signal FLOSS
- `kernel32.dll`
- `GetProcAddress`
- `LoadLibraryA`
- `http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `.aspack`
- `.adata`
- `.reloc`
- `b'36_^`
- `Ulmbdh`
- `5=(kj[`
- `oXK[7~`
- `.F[Cm~`
- `Hd\;m;`
- `u`Ql:4&`
- `~Y<[Q"`
- `Mc6Mnj$7Qk`
- `[#yP(Wd`
- `=oH]*Q`
- `VirtualAlloc`
- `VirtualFree`
- `kernel32.dll`
- `ExitProcess`
- `user32.dll`
- `MessageBoxA`
- `wsprintfA`
- `LOADER ERROR`
- `The procedure entry point %s could not be located in the dynamic link library %s`
- `The ordinal %u could not be located in the dynamic link library %s`
- `(08@P`p`
- `GetProcAddress`
- `GetModuleHandleA`
- `LoadLibraryA`
- `msvbvm60.dll`
- `_CIcos`
- `= Rich`
- ``.rdata`
- `@.data`
- `@.reloc`
- `>Mapplicable to your use of the programs in excess of your license rights. If you do not pay, Oracle can end your technical`
- `important and together create this contract that applies to you. You can review linked terms by pasting`
- `terminated leases and repossessed assets, plus (5) Original cost of assets underlying leases and loans, originated and active on`
- `will be severed and proceed in a court of law, with the remaining parts proceeding in arbitration. If any`
- `means including purchase orders transmitted from Oracle Purchasing) must be licensed separately.`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00409001
```asm
┌ 11: entry0 ();
│           0x00409001      60             pushal
│           0x00409002      e803000000     call 0x40900a
└       ┌─< 0x00409007      e9eb045d45     jmp 0x459d94f7
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r
- Found XOR 00 position 00003AD6: 00000120 ........!..L.!This program cannot be r
- Found XOR 00 position 0000F499: 000000D8 ........!..L.!This program cannot be r
- Found XOR 00 position 000172C1: 00000078 ........!..L.!This program cannot be r
- Found XOR 00 position 0002FFFF: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 00035E5E: 000000B8 ........!..L.!This program cannot be r
- Found XOR 00 position 00039934: 00000120 ........!..L.!This program cannot be r
- Found XOR 00 position 000452F7: 000000D8 ........!..L.!This program cannot be r
- Found XOR 00 position 0004D11F: 00000078 ........!..L.!This program cannot be r
- Found XOR 00 position 00065E5D: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 0006BCBC: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 00071B1B: 000000F0 ........!..L.!This program cannot be r
- Found XOR 00 position 000931B2: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 00099011: 000000F0 ........!..L.!This program cannot be r
- Found XOR 00 position 000BA6A8: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 000C0507: 000000E8 ........!..L.!This program cannot be r
- Found XOR 00 position 000C3F06: 000000E0 ........!..L.!This program cannot be r
- Found XOR 00 position 000C7B05: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 000CD964: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 000D37C3: 00000108 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
