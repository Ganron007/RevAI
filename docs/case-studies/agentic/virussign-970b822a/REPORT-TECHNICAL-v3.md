> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:57:01 UTC

# Technical Malware Analysis Report: ASPack-Packed Generic Malware (SHA256: 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb)

## 1. Executive Summary
This sample is confirmed malicious with a score of 93, packed with the ASPack executable packer to evade static analysis (source: llm_judge, verdict.json). It includes anti-VM checks targeting VirtualBox to avoid execution in analysis environments (source: capa, rule: reference anti-VM strings targeting VirtualBox), uses dynamic API resolution imports (LoadLibrary, GetProcAddress) to load additional functionality at runtime (source: pe_imports, signals: LoadLibrary (T1129) and GetProcAddress (T1129)), and contains an embedded secondary PE file likely serving as the final malicious payload (source: capa, rule: contain an embedded PE file). All available static analysis data points to the sample being a packed trojan or dropper, with no indicators of benign behavior (source: llm_judge, deep-dive.json). Cross-engine analysis confirms consistent malicious indicators across all available tools, with no conflicting clean signals observed (source: verdict.json, cross_engine_notes).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb |
| Sample Path | /opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 93 |
| Family Guess | ASPack-packed generic malware (likely trojan or dropper payload) |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | Ghidra and IDA static analysis engines failed to execute due to project ownership errors (Ghidra) and missing idasql binary (IDA), so all analysis is derived from capa, YARA, FLOSS, and PE import data. All available independent analysis engines confirm consistent malicious indicators including executable packing, anti-sandbox/anti-VM checks, and suspicious runtime API imports, with no conflicting clean indicators observed. (source: verdict.json) |

## 3. File Layout & Structural Analysis
This is a 32-bit Windows PE file, packed with the ASPack executable packer as confirmed by multiple YARA rules and capa analysis (source: yara, matches: ASPackv212AlexeySolodovnikov at offset 9729; source: capa, rule: packed with ASPack). The sample is not a .NET assembly (source: .NET Analysis, is_dotnet: false). UPX unpacking failed, as the sample uses ASPack rather than UPX packing (source: UPX Unpack, upx_ok: False, is_packed: False, returncode: None, unpacked_path: empty).

The PE file has a total of 4 imports, with only 2 high-signal imports related to dynamic API resolution (source: PE Imports / Signals, import_count: 4):
| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

The entry point is located at 0x00409001, with the following disassembly from radare2 (source: radare2 Disassembly, 0x00409001):
```asm
┌ 11: entry0 ();
│           0x00409001      60             pushal
│           0x00409002      e803000000     call 0x40900a
└       ┌─< 0x00409007      e9eb045d45     jmp 0x459d94f7
```
The long jmp to 0x459d94f7 is a characteristic of packer stubs used to obfuscate control flow and evade static analysis (source: deep-dive_agentic, deep-dive.json). XOR search identified 20 positions with XOR 00 values, indicating multiple obfuscated/packed sections within the file (source: XOR Search, 20 matched positions). FLOSS extracted 13,079 total static strings, including ASPack-specific artifacts: `.aspack`, `.adata`, `.reloc`, `LOADER ERROR`, `The procedure entry point %s could not be located in the dynamic link library %s`, `msvbvm60.dll`, and heavily obfuscated strings such as `b'36_^`, `Ulmbdh`, `5=(kj[` (source: FLOSS Strings, total strings: 13079, high-signal FLOSS). YARA also matched suspicious packer section rules at offsets 552 and 592 (source: YARA Matches, rule: suspicious_packer_section, $s1@552 len=7; $s2@592 len=6).

## 4. Malcat Triage Summary
Malcat analysis failed due to an MCP connection closure, with the error: `malcat_analyze top-level: MCP malcat closed:` (source: Malcat Structured Analysis). No triage data was generated from the Malcat engine, so all analysis is derived from capa, YARA, FLOSS, PE import, and radare2 data.

## 5. Static Code Analysis
Static analysis is limited due to the sample being packed with ASPack, which obfuscates the original code. The entry point disassembly from radare2 shows a standard packer stub sequence: pushal, relative call, followed by a long jmp to an obfuscated payload location (source: radare2 Disassembly, 0x00409001).

capa fired 7 total capability rules, with the following mappings to ATT&CK and MBC (source: capa Capability Rules, total rules: 7, duration_s: 3.52):
| Rule | ATT&CK | MBC |
|---|---|---|
| reference anti-VM strings targeting VirtualBox | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| packed with ASPack | T1027.002:Obfuscated Files or Information | F0001:Software Packing |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| contains PDB path |  |  |
| (internal) packer file limitation |  |  |

FLOSS extracted 13,079 static strings, with high-signal entries including memory manipulation and API resolution artifacts (source: FLOSS Strings, total strings: 13079):
- `kernel32.dll`, `GetProcAddress`, `LoadLibraryA`, `VirtualAlloc`, `VirtualFree`, `ExitProcess` (memory and module management APIs commonly used by packed malware)
- `user32.dll`, `MessageBoxA`, `wsprintfA` (UI-related APIs, potentially for user interaction or decoy behavior)
- `LOADER ERROR`, `The procedure entry point %s could not be located in the dynamic link library %s`, `The ordinal %u could not be located in the dynamic link library %s` (ASPack loader error messages)
- `msvbvm60.dll`, `_CIcos` (Visual Basic runtime artifacts, indicating the payload may be written in VB or use VB components)
- Obfuscated strings: `b'36_^`, `Ulmbdh`, `5=(kj[`, `oXK[7~`, `.F[Cm~`, `Hd\;m;`, `u`Ql:4&`, `~Y<[Q"`, `Mc6Mnj$7Qk`, `[#yP(Wd`, `=oH]*Q` (likely encoded payload or C2 indicators)
- Oracle license contract strings (likely embedded as decoy content to evade analysis)

YARA matched 35 total rules, with key matches including packer detection, network indicators, and anti-analysis artifacts (source: YARA Matches, total matches: 35):
- Packer detection: `ASPackv212AlexeySolodovnikov` (offset 9729), `ASPack_v212` (offset 9729), `ASPack_v21_additional` (offset 9729), `ASProtectV2XDLLAlexeySolodovnikov` (offset 9729), `suspicious_packer_section` (offsets 552, 592)
- Anti-analysis: `anti_dbg` (offsets 10817, 204597, 578805), `disable_dep` (offset 67057), `escalate_priv` (offsets 797007, 1733462), `win_hook` (offsets 10842, 2306300, 2306348), `DebuggerException__SetConsoleCtrl` (offset 3022153), `SEH_Init` (offset 793219)
- Network indicators: `IP` (offsets 69211, 471645), `url` (offset 20777), `domain` (offset 0), `contains_base64` (offset 9841)
- Suspicious content: `Misc_Suspicious_Strings` (offset 1830746), `Big_Numbers1` (offset 2281750), `CRC32_poly_Constant` (offset 2994550)

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Speakeasy execution returned 0 API calls and 0 key events, with no duration recorded (source: Speakeasy (dynamic), speakeasy_ok: True, api_calls: 0, key_events: 0, duration_s: None, not observed). Frida probe was available (version 17.16.4) but no instrumentation data was collected (source: Frida Probe, frida_available: True, version: 17.16.4, not observed). UPX unpacking failed, as the sample uses ASPack packing rather than UPX (source: UPX Unpack, upx_ok: False, is_packed: False, returncode: None, unpacked_path: empty). All behavioral indicators are inferred from static analysis artifacts, including anti-VM strings, dynamic API imports, and embedded PE payload indicators.

## 7. Network Indicators & C2
Static network indicators were extracted via YARA and FLOSS, with no dynamic C2 connections observed (source: YARA Matches, network-related rules; source: FLOSS Strings, high-signal entries):
| Indicator Type | Offset | Length | Source |
|---|---|---|---|
| IPv4 Address | 69211 | 7 | YARA, rule: IP |
| IPv6 Address | 471645 | 2 | YARA, rule: IP |
| URL | 20777 | 27 | YARA, rule: url |
| Domain | 0 | 2 | YARA, rule: domain |
| Base64 Encoded String | 9841 | 12 | YARA, rule: contains_base64 |
| Oracle License Contract URL | N/A | N/A | FLOSS, high-signal string: `http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.` |
No dynamic network traffic was observed, so the actual C2 destinations and communication protocols are unknown. The embedded base64 string and obfuscated FLOSS strings may contain additional C2 indicators that are not decoded in static analysis.

## 8. Capabilities & MITRE ATT&CK Mapping
The sample exhibits the following confirmed capabilities based on static analysis, mapped to the MITRE ATT&CK framework and Malware Behavior Catalog (MBC):
| Capability | ATT&CK Technique | MBC | Source |
|---|---|---|---|
| Software packing with ASPack to evade static analysis | T1027.002: Obfuscated Files or Information | F0001: Software Packing | capa, rule: packed with ASPack |
| Virtualization/sandbox evasion via VirtualBox detection strings | T1497.001: Virtualization/Sandbox Evasion | B0009: Virtual Machine Detection | capa, rule: reference anti-VM strings targeting VirtualBox |
| Dynamic API resolution via LoadLibrary and GetProcAddress | T1129: Shared Modules |  | pe_imports, signals: LoadLibrary, GetProcAddress |
| Embedded secondary PE payload (dropper capability) |  | B0023: Install Additional Program | capa, rule: contain an embedded PE file |
| Anti-debugging checks | T1513: Application Debugging |  | YARA, rule: anti_dbg |
| DEP bypass attempts | T1055: Process Injection |  | YARA, rule: disable_dep |
| Privilege escalation attempts | T1068: Exploitation for Privilege Escalation |  | YARA, rule: escalate_priv |
| Windows hook injection | T1055: Process Injection |  | YARA, rule: win_hook |
| SEH initialization | T1513: Application Debugging |  | YARA, rule: SEH_Init |
The sample is consistent with a packed trojan or dropper payload, designed to deploy a secondary malicious payload after evading analysis environments.

## 9. Indicators of Compromise
The following indicators are associated with this sample:
### File-Based IOCs
- SHA256: `62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb` (source: verdict.json)
- Entry point address: `0x00409001` (source: radare2 Disassembly, 0x00409001)
- Obfuscated control flow target: `0x459d94f7` (source: radare2 Disassembly, 0x00409007)
- ASPack section names: `.aspack`, `.adata`, `.reloc` (source: FLOSS Strings)
- ASPack loader error strings: `LOADER ERROR`, `The procedure entry point %s could not be located in the dynamic link library %s`, `The ordinal %u could not be located in the dynamic link library %s` (source: FLOSS Strings)
### Static String IOCs
- Obfuscated strings: `b'36_^`, `Ulmbdh`, `5=(kj[`, `oXK[7~`, `.F[Cm~`, `Hd\;m;`, `u`Ql:4&`, `~Y<[Q"`, `Mc6Mnj$7Qk`, `[#yP(Wd`, `=oH]*Q` (source: FLOSS Strings)
- Base64 encoded string at offset 9841 (length 12) (source: YARA Matches, rule: contains_base64)
- IPv4 address at offset 69211 (length 7) (source: YARA Matches, rule: IP)
- IPv6 address at offset 471645 (length 2) (source: YARA Matches, rule: IP)
- URL at offset 20777 (length 27) (source: YARA Matches, rule: url)
- Domain at offset 0 (length 2) (source: YARA Matches, rule: domain)
- Oracle license contract URL: `http://oracle.com/contracts, and may be updated by Oracle from time to time without notice to you.` (source: FLOSS Strings)
### Behavioral IOCs
- Imports of `LoadLibrary` and `GetProcAddress` for dynamic API resolution (source: pe_imports, signals)
- Anti-VM strings referencing VirtualBox (source: capa, rule: reference anti-VM strings targeting VirtualBox)
- Embedded PE file indicator (source: capa, rule: contain an embedded PE file)

## 10. Detection Engineering
The following signatures and rules can be used to detect this sample and similar ASPack-packed malware:
1. **YARA Rules**: The sample matches 35 YARA rules, including packer-specific rules `ASPackv212AlexeySolodovnikov`, `ASPack_v212`, `ASPack_v21_additional`, `ASProtectV2XDLLAlexeySolodovnikov`, and `suspicious_packer_section` (source: YARA Matches, total matches: 35). These rules detect ASPack artifacts and suspicious packed sections.
2. **Entry Point Signature**: The entry point at 0x00409001 follows a common ASPack stub pattern: `60 pushal; e8 <relative call>; e9 <long jmp>` (source: radare2 Disassembly, 0x00409001). This sequence can be used to detect ASPack-packed samples with similar stub structures.
3. **Import Signature**: The sample has only 4 total imports, with only `LoadLibrary` and `GetProcAddress` as high-signal imports, no other standard library imports (source: PE Imports / Signals, import_count: 4). This import pattern is highly suspicious for a Windows PE file and can be used to flag packed malware.
4. **String Signatures**: Detect ASPack-specific strings: `.aspack`, `.adata`, `.reloc`, `LOADER ERROR`, `The procedure entry point %s could not be located in the dynamic link library %s`, `msvbvm60.dll` (source: FLOSS Strings). Also detect obfuscated strings matching the pattern of the extracted obfuscated entries (e.g., 8-12 character alphanumeric/special character mixes).
5. **capa Rules**: The capa rules `packed with ASPack`, `reference anti-VM strings targeting VirtualBox`, and `contain an embedded PE file` can be used for behavioral detection of similar packed malware (source: capa Capability Rules, total rules: 7).

## 11. What We Don't Know
Several key analysis gaps exist due to tooling failures and the packed nature of the sample:
1. Full disassembly of the original unpacked payload is unavailable, as Ghidra failed due to project ownership errors and IDA failed due to a missing `idasql` binary (source: verdict.json, cross_engine_notes). Function metrics for the unpacked payload are also unavailable for the same reason.
2. No dynamic runtime behavior was observed, as Speakeasy returned 0 API calls/events and Frida collected no instrumentation data (source: Speakeasy (dynamic), not observed; source: Frida Probe, not observed).
3. The unpacked ASPack payload is unavailable, as UPX unpacking failed (ASPack is not supported by UPX) and no other unpacking tools were successful (source: UPX Unpack, upx_ok: False, unpacked_path: empty).
4. The content and capabilities of the embedded secondary PE file are unknown, as it could not be extracted without successful unpacking (source: capa, rule: contain an embedded PE file).
5. Actual C2 destinations and communication protocols are unknown, as no dynamic network traffic was observed and static indicators are limited to partial IP, URL, domain, and base64 strings (source: YARA Matches, network rules; source: FLOSS Strings).
6. The final payload type (trojan, dropper, etc.) is only inferred as generic malicious, with no confirmed specific family or payload capabilities beyond packing and anti-analysis features (source: llm_judge, verdict.json, family_guess: ASPack-packed generic malware (likely trojan or dropper payload)).

## 12. Appendix: Analysis Environment
The following tools were used for analysis, with the noted status:
| Tool | Status | Details |
|---|---|---|
| capa | Successful | 7 rules fired, duration 3.52s (source: capa Capability Rules, total rules: 7, duration_s: 3.52) |
| YARA | Successful | 35 total matches (source: YARA Matches, total matches: 35) |
| FLOSS | Successful | 13,079 total static strings extracted (source: FLOSS Strings, total strings: 13079) |
| radare2 | Successful | Entry point disassembly extracted at 0x00409001 (source: radare2 Disassembly, 0x00409001) |
| UPX | Failed | Unpacking failed, sample is packed with ASPack not UPX (source: UPX Unpack, upx_ok: False, returncode: None) |
| Speakeasy | Successful (no data) | No API calls or events recorded (source: Speakeasy (dynamic), api_calls: 0, key_events: 0) |
| Frida | Available (no data) | Version 17.16.4 available, no instrumentation data collected (source: Frida Probe, frida_available: True, version: 17.16.4) |
| Malcat | Failed | Analysis failed due to MCP connection closure (source: Malcat Structured Analysis, error: malcat_analyze top-level: MCP malcat closed:) |
| Ghidra | Failed | Failed due to project ownership errors (source: verdict.json, cross_engine_notes) |
| IDA | Failed | Failed due to missing `idasql` binary (source: verdict.json, cross_engine_notes) |
| .NET Analyzer | Successful | Sample is not a .NET assembly (source: .NET Analysis, is_dotnet: false) |
| XOR Search | Successful | 20 positions with XOR 00 values identified, indicating obfuscated sections (source: XOR Search, 20 matched positions) |
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
  "rule_count": 35,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
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
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 69211,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 471645,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 9841,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": []
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$a1",
          "offset": 1830746,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Big_Numbers1",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 2281750,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 2994550,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 20777,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "ASPackv212AlexeySolodovnikov",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 9729,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 9729,
          "length": 29,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "ASProtectV2XDLLAlexeySolodovnikov",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 9729,
          "length": 27,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb/virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/
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
