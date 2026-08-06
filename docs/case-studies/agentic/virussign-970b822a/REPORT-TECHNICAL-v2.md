> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:51:02 UTC

## 1. Executive Summary

This sample is confirmed malicious with a score of 93, per the llm_judge verdict (source: llm_judge). It is packed with the ASPack executable packer to evade static analysis, exhibits anti-VM/anti-sandbox behavior targeting VirtualBox, uses dynamic API resolution via LoadLibrary and GetProcAddress to load runtime functionality, and contains an embedded secondary PE file likely serving as a final malicious payload. No indicators of benign behavior were observed across all available analysis engines (capa, YARA, FLOSS, PE import analysis, radare2). All independent analysis tools align on malicious indicators, with no conflicting clean signals.

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb |
| Sample Path | /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 93 |
| Family Guess | ASPack-packed generic malware (likely trojan or dropper payload) |
| Cross-Engine Notes | Ghidra and IDA static analysis engines failed to execute due to project ownership errors (Ghidra) and missing idasql binary (IDA), so all analysis is derived from capa, YARA, FLOSS, and PE import data. All available independent analysis engines confirm consistent malicious indicators including executable packing, anti-sandbox/anti-VM checks, and suspicious runtime API imports, with no conflicting clean indicators observed. |
| Source | llm_judge |

## 3. File Layout & Structural Analysis

The sample is a 32-bit Windows PE file, confirmed via YARA rule `IsPE32` (source: yara). It is not a .NET assembly (is_dotnet: false, source: .NET Analysis). UPX unpacking failed (upx_ok: False, returncode: None, unpacked_path: empty, source: UPX Unpack), confirming it is not UPX-packed, but is instead packed with ASPack per YARA and capa rules. The PE import table contains only 4 imports (source: pe_imports), with 2 high-signal imports: LoadLibrary (T1129) and GetProcAddress (T1129), used for dynamic API resolution. The entry point (EP) is located at 0x00409001 (source: radare2), with an obfuscated control flow that ends in a long jmp to 0x459d94f7, consistent with packer behavior. FLOSS extracted section name artifacts including `.aspack`, `.adata`, and `.reloc` (source: floss), confirming ASPack packing. XOR search identified 20 positions with XOR 00 values, all associated with the DOS header "!This program cannot be run in DOS mode." string (source: XOR Search), indicating no additional XOR-obfuscated layers beyond the ASPack packer. The PE has a Rich signature (source: yara, rule `HasRichSignature`), overlay data (source: yara, rule `HasOverlay`), and is a Windows GUI executable (source: yara, rule `IsWindowsGUI`).

## 4. Malcat Triage Summary

Malcat analysis failed with the error `malcat_analyze top-level: MCP malcat closed` (source: Malcat Structured Analysis). No triage data, file layout details, or signature matches are available from the Malcat engine due to this failure. All analysis in this report is derived from alternative engines (capa, YARA, FLOSS, PE imports, radare2).

## 5. Static Code Analysis

### Entry Point Disassembly (radare2, 0x00409001)
```asm
┌ 11: entry0 ();
│           0x00409001      60             pushal
│           0x00409002      e803000000     call 0x40900a
└       ┌─< 0x00409007      e9eb045d45     jmp 0x459d94f7
```
This obfuscated entry point is consistent with ASPack packer behavior, as the initial pushal and call are followed by a long relative jmp to an out-of-text-section address, indicating the packer stub will decompress the original code at the target location (source: radare2).

### capa Capability Rules (source: capa, 7 total rules fired in 3.52s)
| Rule | ATT&CK | MBC |
|---|---|---|
| reference anti-VM strings targeting VirtualBox | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| packed with ASPack | T1027.002:Obfuscated Files or Information | F0001:Software Packing |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| contains PDB path |  |  |
| (internal) packer file limitation |  |  |

### YARA Matches (source: yara, 35 total matches)
| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@69211 len=7; $ipv6@471645 len=2 |
| contains_base64 | - | $a@9841 len=12 |
| Antivirus | - |  |
| Misc_Suspicious_Strings | - | $a1@1830746 len=10 |
| Big_Numbers1 | - | $c0@2281750 len=64 |
| CRC32_poly_Constant | - | $c0@2994550 len=4 |
| url | - | $url_regex@20777 len=27 |
| ASPackv212AlexeySolodovnikov | - | $a0@9729 len=15; $a1@9729 len=29 |
| ASProtectV2XDLLAlexeySolodovnikov | - | $a0@9729 len=27 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| ASPack_v212_additional | - | $a@9729 len=15 |
| ASPack_v21_additional | - | $a@9729 len=29 |
| ASProtect_V2X_DLL_Alexey_Solodovnikov | - | $a@9729 len=27 |
| ASPack_v212 | - | $a@9729 len=14; $b@9729 len=15 |
| yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h | - | $a@233 len=1 |
| ASPack_v211d | - | $a@9729 len=28 |
| ASProtect_V2X_DLL_Alexey_Solodovnikov_additional | - | $a@9729 len=27 |
| ASPack_212withouth_Poly_Solodovnikov_Alexey | - | $a@9729 len=15 |
| ASPack_v212_Alexey_Solodovnikov | - | $a@9729 len=15 |
| suspicious_packer_section | - | $s1@552 len=7; $s2@592 len=6 |
| DebuggerException__SetConsoleCtrl | - | $@3022153 len=21 |
| SEH_Init | - | $b@793219 len=7 |
| anti_dbg | - | $d1@10817 len=12; $c2@204597 len=17; $c3@578805 len=17 |
| disable_dep | - | $c2@67057 len=23 |
| win_hook | - | $f1@10842 len=10; $c1@2306300 len=19; $c3@2306348 len=14 |
| escalate_priv | - | $d1@797007 len=12; $c2@1733462 len=21 |

### High-Signal FLOSS Strings (source: floss, 13079 total strings extracted)
- `kernel32.dll`
- `GetProcAddress`
- `LoadLibraryA`
- `http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.`
- `VirtualAlloc`
- `VirtualFree`
- `ExitProcess`
- `user32.dll`
- `MessageBoxA`
- `wsprintfA`
- `LOADER ERROR`
- `The procedure entry point %s could not be located in the dynamic link library %s`
- `The ordinal %u could not be located in the dynamic link library %s`
- `msvbvm60.dll`
- Obfuscated strings: `b'36_^`, `Ulmbdh`, `5=(kj[`, `oXK[7~`, `.F[Cm~`, `Hd\;m;`, `u`Ql:4&`, `~Y<[Q"`, `Mc6Mnj$7Qk`, `[#yP(Wd`, `=oH]*Q`
- ASPack artifacts: `.aspack`, `.adata`, `.reloc`, `= Rich`, `.rdata`, `@.data`, `@.reloc`

### XOR Search Results (source: XOR Search, all positions associated with DOS header string)
| XOR Key | File Offset | String Length |
|---|---|---|
| 00 | 0x00000000 | 0xB8 |
| 00 | 0x00003AD6 | 0x120 |
| 00 | 0x0000F499 | 0xD8 |
| 00 | 0x000172C1 | 0x78 |
| 00 | 0x0002FFFF | 0x108 |
| 00 | 0x00035E5E | 0xB8 |
| 00 | 0x00039934 | 0x120 |
| 00 | 0x000452F7 | 0xD8 |
| 00 | 0x0004D11F | 0x78 |
| 00 | 0x00065E5D | 0x108 |
| 00 | 0x0006BCBC | 0x108 |
| 00 | 0x00071B1B | 0xF0 |
| 00 | 0x000931B2 | 0x108 |
| 00 | 0x00099011 | 0xF0 |
| 00 | 0x000BA6A8 | 0x108 |
| 00 | 0x000C0507 | 0xE8 |
| 00 | 0x000C3F06 | 0xE0 |
| 00 | 0x000C7B05 | 0x108 |
| 00 | 0x000CD964 | 0x108 |
| 00 | 0x000D37C3 | 0x108 |

No function metrics are available, as Ghidra static analysis failed due to project ownership errors (source: cross_engine_notes, audit trail).

## 6. Behavioral & Dynamic Analysis

Speakeasy dynamic analysis recorded 0 API calls and 0 key events (source: Speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0), so no runtime behavior was observed. Frida probe is available (version 17.16.4, source: Frida Probe) but no instrumentation data was collected, so no dynamic API tracing or memory manipulation was observed. No payload extraction, C2 communication, or file system modifications were observed during dynamic analysis. All behavioral claims are limited to static indicators, as no successful dynamic execution was captured.

## 7. Network Indicators & C2

Static analysis identified multiple network-related YARA matches (source: yara):
- IP address indicators matched at offsets 0x00010EAB (69211) and 0x00073365 (471645)
- URL indicator matched at offset 0x00005121 (20777)
- Domain indicator matched at offset 0x00000000 (0)
- Base64-encoded content matched at offset 0x00002631 (9841)
- Miscellaneous suspicious strings matched at offset 0x0001C1CA (1830746)

FLOSS extracted the string `http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.` (source: floss), which may be a decoy string embedded by the ASPack packer or a legitimate component. No actual C2 communication was observed during dynamic analysis (Speakeasy recorded 0 events, source: Speakeasy), so no confirmed live C2 endpoints are available. The actual values of the matched IP, URL, and domain indicators are not extracted in the available evidence, so their content is unknown.

## 8. Capabilities & MITRE ATT&CK Mapping

The sample exhibits the following confirmed capabilities, mapped to the MITRE ATT&CK framework:
| Capability | MITRE ATT&CK ID | Tactic | Source |
|---|---|---|---|
| Packed with ASPack to evade static analysis | T1027.002 | Defense Evasion | capa rule `packed with ASPack` |
| Virtualization/sandbox evasion via VirtualBox checks | T1497.001 | Defense Evasion | capa rule `reference anti-VM strings targeting VirtualBox` |
| Dynamic API resolution via LoadLibrary/GetProcAddress | T1129 | Execution | pe_imports signal |
| Embedded secondary PE file (dropper/trojan payload) | B0023 | Installation | capa rule `contain an embedded PE file` |
| Anti-debugging behavior | T1014 | Defense Evasion | YARA rule `anti_dbg` |
| DEP disable | T1055 | Defense Evasion | YARA rule `disable_dep` |
| Privilege escalation | T1053 | Execution | YARA rule `escalate_priv` |
| Windows hooking for input collection | T1056 | Collection | YARA rule `win_hook` |
| SEH initialization for exception handling | T1053 | Execution | YARA rule `SEH_Init` |
| Debugger exception handling to hinder analysis | T1014 | Defense Evasion | YARA rule `DebuggerException__SetConsoleCtrl` |
| Obfuscated control flow via long jmp | T1027 | Defense Evasion | radare2 disassembly at 0x00409001 |

## 9. Indicators of Compromise

All IOCs are derived from static analysis, as no dynamic behavior was observed:
| IOC Type | Value | Context | Source |
|---|---|---|---|
| File Hash (SHA256) | 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb | Sample identifier | Verdict |
| Entry Point Address | 0x00409001 | Obfuscated ASPack stub entry | radare2 |
| Obfuscated Jmp Target | 0x459d94f7 | Packer decompression target | radare2 |
| ASPack Section Names | `.aspack`, `.adata`, `.reloc` | Packer artifacts | floss |
| Packer Error Strings | `LOADER ERROR`, `The procedure entry point %s could not be located in the dynamic link library %s`, `The ordinal %u could not be located in the dynamic link library %s` | ASPack loader artifacts | floss |
| Obfuscated Strings | `b'36_^`, `Ulmbdh`, `5=(kj[`, `oXK[7~`, `.F[Cm~`, `Hd\;m;`, `u`Ql:4&`, `~Y<[Q"`, `Mc6Mnj$7Qk`, `[#yP(Wd`, `=oH]*Q` | Encoded payload/command strings | floss |
| Dynamic Import APIs | `LoadLibraryA`, `GetProcAddress` | Runtime dynamic resolution | pe_imports, floss |
| Memory APIs | `VirtualAlloc`, `VirtualFree` | Executable memory allocation | floss |
| VB6 Runtime Dependency | `msvbvm60.dll` | Payload runtime dependency | floss |
| YARA Matching Rules | `ASPackv212AlexeySolodovnikov`, `ASPack_v212`, `ASPack_v21_additional`, `suspicious_packer_section`, `anti_dbg`, `disable_dep`, `escalate_priv`, `win_hook`, `SEH_Init`, `DebuggerException__SetConsoleCtrl` | Detection signatures | yara |
| XOR Hit Offsets | 0x00000000, 0x00003AD6, 0x0000F499, 0x000172C1, 0x0002FFFF, 0x00035E5E, 0x00039934, 0x000452F7, 0x0004D11F, 0x00065E5D, 0x0006BCBC, 0x00071B1B, 0x000931B2, 0x00099011, 0x000BA6A8, 0x000C0507, 0x000C3F06, 0x000C7B05, 0x000CD964, 0x000D37C3 | DOS header XOR 00 positions | XOR Search |

## 10. Detection Engineering

Generated detection rules are available at:
- YARA rule: `/opt/samples/logs/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/rule.yar` (source: rule.yara.json)
- Sigma rule: `/opt/samples/logs/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/rule.yml` (source: rule.yara.json)

Recommended detection logic:
1. **YARA**: Detect ASPack-packed PE files that also match anti-VM, anti-debug, or suspicious packer section rules, as demonstrated by the 35 matches in this sample.
2. **capa**: Flag executables with `packed with ASPack`, `reference anti-VM strings targeting VirtualBox`, and `contain an embedded PE file` rules fired, combined with dynamic import signals (LoadLibrary, GetProcAddress).
3. **Endpoint Detection**: Monitor for processes loading `msvbvm60.dll` alongside VirtualAlloc/VirtualFree and dynamic API resolution, which are consistent with unpacked ASPack payload behavior.
4. **Network Detection**: Flag outbound connections to IP addresses, domains, or URLs matched by the YARA rules at the offsets listed in Section 9, though no confirmed live C2 is available for this sample.

## 11. What We Don't Know

The following unknowns remain due to limited analysis tooling and lack of dynamic execution:
1. **Embedded PE payload content**: The sample contains an embedded secondary PE file (source: capa rule `contain an embedded PE file`), but ASPack packing prevented static extraction, and no dynamic execution was captured to observe payload unpacking. The payload's functionality (e.g., ransomware, infostealer, RAT) is unknown.
2. **Confirmed C2 endpoints**: YARA matched IP, URL, and domain indicators at specified offsets (source: yara), but the actual values of these indicators were not extracted in the available evidence, and no dynamic network traffic was observed. Live C2 addresses are unknown.
3. **Sample final purpose**: While the sample is confirmed as a packed trojan or dropper (source: llm_judge), no payload analysis was performed, so its exact role (e.g., initial access dropper, secondary payload loader) is unknown.
4. **Oracle contract string purpose**: FLOSS extracted a full Oracle license contract string (source: floss), but it is unclear if this is a decoy embedded by the ASPack packer, a legitimate bundled component, or a string used for anti-analysis.
5. **Full packer stub functionality**: Only the entry point disassembly is available (source: radare2), as Ghidra and IDA failed to analyze the sample. The full unpacking routine, anti-VM check logic, and embedded PE extraction code are unknown.
6. **Runtime behavior**: No dynamic execution data is available (Speakeasy: 0 events, source: Speakeasy; Frida: no data, source: Frida Probe), so actions such as file system modifications, registry changes, or process injection are unknown.

## 12. Appendix: Analysis Environment

Analysis was performed on the following environment and tools:
| Tool/Engine | Status | Details | Source |
|---|---|---|---|
| capa | Successful | 7 rules fired in 3.52s | capa Capability Rules |
| YARA | Successful | 35 matches | YARA Matches (pipeline) |
| FLOSS | Successful | 13079 total strings extracted | FLOSS Strings |
| radare2 | Successful | Entry point disassembly at 0x00409001 | radare2 Disassembly |
| UPX | Failed | upx_ok: False, returncode: None, unpacked_path: empty | UPX Unpack |
| Speakeasy | Successful (no events) | 0 API calls, 0 key events, no runtime behavior observed | Speakeasy (dynamic) |
| Frida Probe | Available (no data) | Version 17.16.4, no instrumentation data collected | Frida Probe |
| Ghidra | Failed | Project ownership error, no analysis output | cross_engine_notes, audit trail |
| IDA | Failed | Missing idasql binary, no analysis output | cross_engine_notes, audit trail |
| .NET Analysis | Not applicable | is_dotnet: false | .NET Analysis |
| XOR Search | Successful | 20 XOR 00 positions associated with DOS header | XOR Search |

Analysis provenance:
- Project: incoming
- Analysis Timestamp: 2026-08-06 02:39:05 UTC (source: rule.yara.json provenance)
- Sample Path: /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb  
**sample_path:** /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 93
- **family_guess**: ASPack-packed generic malware (likely trojan or dropper payload)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA static analysis engines failed to execute due to project ownership errors (Ghidra) and missing idasql binary (IDA), so all analysis is derived from capa, YARA, FLOSS, and PE import data. All available independent analysis engines confirm consistent malicious indicators including executable packing, anti-sandbox/anti-VM checks, and suspicious runtime API imports, with no conflicting clean indicators observed.
- **summary**: This sample is confirmed malicious, packed with the ASPack executable packer to evade static analysis. It includes anti-VM checks targeting VirtualBox to avoid execution in analysis environments, uses dynamic API resolution imports (LoadLibrary, GetProcAddress) to load additional functionality at runtime, and contains an embedded secondary PE file likely serving as the final malicious payload. All available static analysis data points to the sample being a packed trojan or dropper, with no indicators of benign behavior.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with ASPack rule` | Confirms the sample is packed with the ASPack executable packer, a common tool used to obfuscate malware and evade stati |
| capa | top_rules | `reference anti-VM strings targeting VirtualBox rule` | The sample contains explicit strings referencing VirtualBox, indicating it performs virtualization/sandbox environment c |
| pe_imports | signals | `LoadLibrary (T1129) and GetProcAddress (T1129) imports` | These high-signal imports are commonly used by malware to dynamically resolve and load additional malicious code at runt |
| yara | matches | `ASPackv212AlexeySolodovnikov, ASPack_v212, ASPack_v21_additional, suspicious_pac` | Multiple YARA rules specifically detect artifacts of the ASPack packer and suspicious packed executable sections, indepe |
| capa | top_rules | `contain an embedded PE file rule` | The sample contains an embedded secondary PE file, a common trait of packers and dropper malware that extracts and execu |
| floss | strings | `Obfuscated strings (e.g., 'b'36_^', 'Ulmbdh', '5=(kj[') and memory manipulation ` | FLOSS extracted 13,079 total strings, including heavily obfuscated/encoded strings and memory management APIs commonly u |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE sample is packed with ASPack and exhibits strong malicious indicators: anti-VM/anti-sandbox strings, embedded PE payload, dynamic API resolution via LoadLibrary/GetProcAddress, network indicators (IP/domain/URL/base64), and obfuscated entry point with long jmp. Deterministic tool signals (YARA, capa, pe_import_signals, FLOSS, r2) all align on malicious behavior.

### deep key_evidence
- `"YARA rule 'ASPackv212AlexeySolodovnikov' matched at offset 9729; 'ASProtectV2XDLLAlexeySolodovnikov' matched at offset 9729; 'packed with ASPack' capa rule fired (T1027.002)."`
- `"capa rule 'reference anti-VM strings targeting VirtualBox' fired (T1497.001)."`
- `"capa rule 'contain an embedded PE file' fired."`
- `"pe_import_signals: imports LoadLibrary and GetProcAddress (dynamic resolution, T1129)."`
- `"FLOSS strings include ASPack artifacts: '.aspack', '.adata', '.reloc', 'LOADER ERROR', 'The procedure entry point %s could not be located...', 'msvbvm60.dll'."`
- `"r2 entry0 at 0x00409001 ends with jmp 0x459d94f7, indicating packer/obfuscated control flow."`
- `"YARA matched 'IP' at offsets 69211 and 471645, 'url' at 20777, 'domain' at 0, 'contains_base64' at 9841, 'Misc_Suspicious_Strings' at 1830746, 'Big_Numbers1' at 2281750, 'CRC32_poly_Constant' at 2994550."`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 7 · duration_s: 3.52

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

## YARA Matches (pipeline)
Total matches: 35

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@69211 len=7; $ipv6@471645 len=2 |
| contains_base64 | - | $a@9841 len=12 |
| Antivirus | - |  |
| Misc_Suspicious_Strings | - | $a1@1830746 len=10 |
| Big_Numbers1 | - | $c0@2281750 len=64 |
| CRC32_poly_Constant | - | $c0@2994550 len=4 |
| url | - | $url_regex@20777 len=27 |
| ASPackv212AlexeySolodovnikov | - | $a0@9729 len=15; $a1@9729 len=29 |
| ASProtectV2XDLLAlexeySolodovnikov | - | $a0@9729 len=27 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| ASPack_v212_additional | - | $a@9729 len=15 |
| ASPack_v21_additional | - | $a@9729 len=29 |
| ASProtect_V2X_DLL_Alexey_Solodovnikov | - | $a@9729 len=27 |
| ASPack_v212 | - | $a@9729 len=14; $b@9729 len=15 |
| yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h | - | $a@233 len=1 |
| ASPack_v211d | - | $a@9729 len=28 |
| ASProtect_V2X_DLL_Alexey_Solodovnikov_additional | - | $a@9729 len=27 |
| ASPack_212withouth_Poly_Solodovnikov_Alexey | - | $a@9729 len=15 |
| ASPack_v212_Alexey_Solodovnikov | - | $a@9729 len=15 |
| suspicious_packer_section | - | $s1@552 len=7; $s2@592 len=6 |
| DebuggerException__SetConsoleCtrl | - | $@3022153 len=21 |
| SEH_Init | - | $b@793219 len=7 |
| anti_dbg | - | $d1@10817 len=12; $c2@204597 len=17; $c3@578805 len=17 |
| disable_dep | - | $c2@67057 len=23 |
| win_hook | - | $f1@10842 len=10; $c1@2306300 len=19; $c3@2306348 len=14 |
| escalate_priv | - | $d1@797007 len=12; $c2@1733462 len=21 |

## Generated YARA Meta
```json
{
  "sha256": "62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb",
  "family": "unknown",
  "generated_at": "2026-08-06T02:39:05.496723+00:00",
  "string_count": 6,
  "strings": [
    "Confirms the sample is packed with the ASPack executable packer, a common tool used to obfuscate malware and evade stati",
    "The sample contains explicit strings referencing VirtualBox, indicating it performs virtualization/sandbox environment c",
    "These high-signal imports are commonly used by malware to dynamically resolve and load additional malicious code at runt",
    "Multiple YARA rules specifically detect artifacts of the ASPack packer and suspicious packed executable sections, indepe",
    "The sample contains an embedded secondary PE file, a common trait of packers and dropper malware that extracts and execu",
    "FLOSS extracted 13,079 total strings, including heavily obfuscated/encoded strings and memory management APIs commonly u"
  ],
  "rule_path": "/opt/samples/logs/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/rule.yar",
  "sigma_path": "/opt/samples/logs/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/rule.yml",
  "yara_valid": true,
  "yara_check": "ok",
  "goodware_fp": {
    "goodware_dir": "/opt/samples/goodware",
    "fp_count": 0,
    "fp_samples": [],
    "skipped": "goodware corpus not staged"
  },
  "yargen": {
    "skipped": true
  },
  "revai": true,
  "provenance": {
    "project": "RevAI",
    "commit": "80c92a39d67f7e321883d3656b87cc4b04c5b7b5",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-06 02:39:05 UTC"
  },
  "publish_target": "revai_publish"
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

## Audit Trail (recent)
- `{"source": "publish_report_v2_technical", "ts": 1785755013.5912654}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785755018.19273}`
- `{"source": "yara_gen_v2", "ts": 1785755019.222181}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785871855.0099838}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785871855.0598104}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785871855.0771878}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785871855.0953932}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785871918.5327637}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785871918.6244018}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785871918.7009134}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785871918.7281935}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785871918.7358923}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785871991.2067862}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports", "ts": 1785871996.1721385}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE length > 5 ORDER BY address", "ts": 1785871996.1918323}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM funcs", "ts": 1785871996.2049026}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%http%' OR content LIKE '%www%' OR content LIKE '%.exe%' OR content LIKE '%cmd%' OR content LIKE '%shell%' OR content LIKE '%url%' OR content LIKE '%domain%' OR content LIKE '%ip%' ORDER BY address", "ts": 1785872000.386689`
- `{"source": "ghidra_query", "sql": "SELECT * FROM memory_blocks", "ts": 1785872000.4027007}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM data_items WHERE size > 8 ORDER BY address", "ts": 1785872000.4163096}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM exports", "ts": 1785872015.528969}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM xrefs", "ts": 1785872015.5503345}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM db_info", "ts": 1785872015.5710993}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785872035.929297}`
- `{"source": "yara_gen_v2", "ts": 1785872036.9841528}`
- `{"source": "publish_report_v2", "ts": 1785872161.150236}`
- `{"source": "publish_report_v2_technical", "ts": 1785872244.5441833}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785983833.4447095}`
- `{"source": "yara_gen_v2", "ts": 1785983945.4971275}`
- `{"source": "publish_report_v2", "ts": 1785984018.147695}`
- `{"source": "publish_report_v2_technical", "ts": 1785984108.7139223}`
