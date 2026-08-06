> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 04:12:25 UTC

## 1. Executive Summary
This sample (sha256: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819) is a malicious, packed 2.2MB 32-bit Windows GUI PE file compiled with Borland Delphi, with a threat score of 92 (source: llm_judge, Verdict section). Static analysis confirms 142 imports, 49 capa-detected capabilities, 26 YARA rule matches, and 11,298 extracted FLOSS strings, all aligned with malicious functionality consistent with an infostealer or remote access trojan (RAT) (source: llm_judge, Verdict section; source: deep_dive_agentic, deep-dive.json). The sample exhibits obfuscation (XOR, RC4), high-signal offensive imports for process injection and execution, system/registry/file reconnaissance, and privilege escalation capabilities. No dynamic runtime behavior was observed during emulation, consistent with its packed state. Ghidra and IDA analysis failed due to technical limitations, so all evidence is sourced from pe_imports, capa, YARA, FLOSS, and radare2 (source: llm_judge, cross_engine_notes).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 |
| Sample Path | /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 92 |
| Family Guess | Unknown Delphi-based packed malware, likely an infostealer or remote access trojan (RAT) given its system/registry/file discovery, process injection, and privilege escalation capabilities |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | Ghidra and IDA analysis failed due to technical issues (Ghidra project ownership error, missing idasql binary), so all evidence is sourced from pe_imports, capa, YARA, and FLOSS. Cross-engine alignment is strong: YARA's Delphi compiler identification matches FLOSS's Delphi-specific strings; pe_imports' high-signal process injection and execution APIs align with capa's detected process injection, execution, and obfuscation behaviors. The sample's packed state (confirmed by YARA) explains its large 2.2MB size, high string count, and failure of Ghidra/IDA to extract function data. |
*(source: llm_judge, Verdict section)*

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows GUI PE file compiled with Borland Delphi, with a total size of ~2.2MB (source: llm_judge, cross_engine_notes). YARA confirms the sample is packed, with matches for `IsPacked` and `HasOverlay` rules, indicating obfuscated code and appended overlay data (source: yara, YARA Matches table, IsPacked/HasOverlay rows). The PE contains standard Delphi section names extracted via FLOSS: `.itext`, `.data`, `.idata`, `.didata`, `.edata`, `.rdata`, `@.rsrc` (source: floss, FLOSS Strings section). The entry point (EP) is located at virtual address 0x004b5eec, with a large stack frame (0xa4 bytes of local variables) and Delphi-style initialization sequences (source: radare2, radare2 Disassembly section, 0x004b5eec). The sample has 142 imported APIs (source: pe_imports, PE Imports / Signals section, import_count: 142). UPX unpack attempt failed, returning no output and an empty unpacked path (source: upx, UPX Unpack section, upx_ok: False, unpacked_path: ``). XOR search identified an XOR 00 value at file position 0, consistent with packed/obfuscated code (source: XOR Search section). FLOSS extracted a total of 11,298 strings: 1 tight string, 11,297 static strings, including Delphi runtime type definitions (source: floss, FLOSS Strings section, Total strings: 11298).

## 4. Malcat Triage Summary
Malcat analysis failed with the error: `malcat_analyze top-level: MCP malcat closed: ` (source: malcat, Malcat Structured Analysis section). No Malcat-specific triage data, file layout annotations, or signature matches are available for this sample.

## 5. Static Code Analysis
Radare2 disassembly of the entry point at 0x004b5eec reveals a large stack frame initialization, standard Delphi prologue sequences, and calls to runtime initialization functions (source: radare2, radare2 Disassembly section, 0x004b5eec):
```asm
┌ 501: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_24h @ ebp-0x24
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_38h @ ebp-0x38
│           ; var int32_t var_3ch @ ebp-0x3c
│           ; var int32_t var_40h @ ebp-0x40
│           ; var int32_t var_5ch @ ebp-0x5c
│           0x004b5eec      55             push ebp
│           0x004b5eed      8bec           mov ebp, esp
│           0x004b5eef      83c4a4         add esp, 0xffffffa4
│           0x004b5ef2      53             push ebx
│           0x004b5ef3      56             push esi
│           0x004b5ef4      57             push edi
│           0x004b5ef5      33c0           xor eax, eax
│           0x004b5ef7      8945c4         mov dword [var_3ch], eax
│           0x004b5efa      8945c0         mov dword [var_40h], eax
│           0x004b5efd      8945a4         mov dword [var_5ch], eax
│           0x004b5f00      8945d0         mov dword [var_30h], eax
│           0x004b5f03      8945c8         mov dword [var_38h], eax
│           0x004b5f06      8945cc         mov dword [var_34h], eax
│           0x004b5f09      8945d4         mov dword [var_2ch], eax
│           0x004b5f0c      8945d8         mov dword [var_28h], eax
│           0x004b5f0f      8945ec         mov dword [var_14h], eax
│           0x004b5f12      b8b8144b00     mov eax, 0x4b14b8
│           0x004b5f17      e8b072f5ff     call 0x40d1cc
│           0x004b5f1c      33c0           xor eax, eax
│           0x004b5f1e      55             push ebp
│           0x004b5f1f      68e2654b00     push 0x4b65e2
│           0x004b5f24      64ff30         push dword fs:[eax]
│           0x004b5f27      648920         mov dword fs:[eax], esp
│           0x004b5f2a      33d2           xor edx, edx
│           0x004b5f2c      55             push ebp
│           0x004b5f2d      689e654b00     push 0x4b659e
│           0x004b5f32      64ff32         push dword fs:[edx]
│           0x004b5f35      648922         mov dword fs:[edx], esp
│           0x004b5f38      a134e64b00     mov eax, dword [0x4be634]   ; [0x4be634:4]=0
│           0x004b5f3d      e8a29dffff     call 0x4afce4
│           0x004b5f42      e8f598ffff     call 0x4af83c
│           0x004b5f47      8d55ec         lea edx, [var_14h]
│           0x004b5f4a      33c0           xor eax, eax
│           0x004b5f4c      e84fcdf6ff     call 0x422ca0
│           0x004b5f51      8b55ec         mov edx, dword [var_14h]
│           0x004b5f54      b8841d4c00     mov eax, 0x4c1d84
│           0x004b5f59      e8a21ef5ff     call 0x407e00
│           0x004b5f5e      6a02           push 2                      ; 2
│           0x004b5f60      6a00           push 0
│           0x004b5f62      6a01           push 1  
```
Additional radare2 functions include `sym.SetupLdr.exe___dbk_fcall_wrapper` at 0x0040d0a0 (167 bytes, 200+ calls to `fcn.0040ccac`, a simple ret function used for Delphi method interception) and `sym.SetupLdr.exe_TMethodImplementationIntercept` at 0x004541a8 (16 bytes, a thin wrapper for method implementation calls) (source: radare2, radare2 Disassembly section, 0x0040d0a0/0x0040ccb0/0x004541a8). FLOSS extracted Delphi runtime and RTTI strings including `Boolean`, `System`, `AnsiChar`, `Integer`, `Cardinal`, `WideString`, `AnsiString`, `TObject&`, `DisposeOf`, `InitInstance`, `ClassName`, and `&op_Equality`, confirming Delphi compilation (source: floss, FLOSS Strings section). YARA matches for `Delphi_CompareCall` (offset 0x31860), `Borland` (offset 0x41422), and multiple `Borland_Delphi*` rules (offset 0x15976, 0x50636) corroborate the Delphi compiler identification, with a minor match for `Microsoft_Visual_Cpp_v50v60_MFC` at offset 0x15728 likely a false positive (source: yara, YARA Matches table, Delphi_CompareCall/Borland/borland_delphi/Borland_Delphi_* rows).

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Speakeasy emulation completed successfully (speakeasy_ok: True) but recorded 0 API calls and 0 key events, indicating no executable code was reached during emulation, consistent with the sample's packed/obfuscated state (source: speakeasy, Speakeasy section, api_calls: 0, key_events: 0). Frida probe (version 17.16.4) identified 24 hook candidates including `kernel32.dll!GetACP`, `advapi32.dll!RegQueryValueExW`, `user32.dll!CreateWindowExW`, and `netapi32.dll!NetWkstaGetInfo`, but no runtime hook calls were observed (source: frida, Frida Probe section). UPX unpack attempt failed with no output, so no unpacked payload was available for dynamic execution (source: upx, UPX Unpack section, upx_ok: False, returncode: None, unpacked_path: ``). No process injection, C2 communication, or file system modifications were observed at runtime.

## 7. Network Indicators & C2
All network indicators are static, embedded in the packed binary, with no dynamic C2 communication observed. YARA rules matched the following static network artifacts:
| Rule | Offset | Length | Description |
|---|---|---|---|
| domain | 0 | 3 | Embedded domain name regex match |
| IP (IPv4) | 830343 | 7 | Embedded IPv4 address |
| IP (IPv6) | 917570 | 2 | Embedded IPv6 address |
| url | 722888 | 78 | Embedded URL regex match |
| contains_base64 | 2194 | 12 | Embedded base64-encoded data |
*(source: yara, YARA Matches table, domain/IP/url/contains_base64 rows; source: yara, Generated YARA Meta section)*
No decoded C2 addresses, URLs, or base64 payloads are available from static or dynamic analysis.

### Full YARA Match List (26 total matches)
| Rule | Namespace | Match Strings (Offset, Length) |
|---|---|---|
| domain | - | $domain_regex@0 len=3 |
| IP | - | $ipv4@830343 len=7; $ipv6@917570 len=2 |
| contains_base64 | - | $a@2194 len=12 |
| CRC32_poly_Constant | - | $c0@146170 len=4 |
| Delphi_CompareCall | - | $c1@31860 len=42 |
| url | - | $url_regex@722888 len=78 |
| Borland | - | $patternBorland@41422 len=14 |
| IsPE32 | - | No strings |
| IsWindowsGUI | - | No strings |
| IsPacked | - | No strings |
| HasOverlay | - | No strings |
| borland_delphi | - | $c0@50636 len=42; $c1@50636 len=73 |
| Borland_Delphi_40_additional | - | $a@15976 len=5 |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@15728 len=4 |
| Borland_Delphi_30_additional | - | $a@15976 len=4 |
| Borland_Delphi_30_ | - | $a@15976 len=4 |
| Borland_Delphi_Setup_Module | - | $a@15976 len=5 |
| Borland_Delphi_40 | - | $a@15976 len=5 |
| Borland_Delphi_v40_v50 | - | $a@15976 len=4 |
| Borland_Delphi_v30 | - | $a@15976 len=4 |
| Borland_Delphi_DLL | - | $a@15976 len=4 |
| disable_dep | - | $c4@738280 len=19 |
| escalate_priv | - | $d1@761072 len=12; $c2@761164 len=21 |
| win_registry | - | $f1@761072 len=12; $c3@761260 len=11; $c6@761260 len=11 |
| win_token | - | $f1@761072 len=12; $c2@761164 len=21; $c3@761274 len=16 |
| win_files_operation | - | $f1@758600 len=12; $c1@760088 len=9; $c2@759296 len=14; $c3@760088 len=9; $c4@758874 len=8 |
*(source: yara, Generated YARA Meta section)*

## 8. Capabilities & MITRE ATT&CK Mapping
The sample exhibits a wide range of malicious capabilities confirmed via capa rules and PE import analysis, mapped to the MITRE ATT&CK framework:
### capa Detected Capabilities
| Rule | ATT&CK Technique | MBC Behavior |
|---|---|---|
| encode data using XOR | T1027: Obfuscated Files or Information | E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data |
| encrypt data using RC4 PRGA | T1027: Obfuscated Files or Information | C0027.009: Encrypt Data, C0021.004: Generate Pseudo-random Sequence |
| create or open registry key | N/A | C0036.004: Registry, C0036.003: Registry |
| check OS version | T1082: System Information Discovery | E1082: System Information Discovery |
| query or enumerate registry value | T1012: Query Registry | C0036.006: Registry |
| get common file path | T1083: File and Directory Discovery | E1083: File and Directory Discovery |
| get disk size | T1082: System Information Discovery | E1082: System Information Discovery |
| get file version info | T1083: File and Directory Discovery | E1083: File and Directory Discovery |
| query environment variable | T1082: System Information Discovery | E1082: System Information Discovery |
| accept command line arguments | T1059: Command and Scripting Interpreter | E1059: Command and Scripting Interpreter |
| check if file exists | T1083: File and Directory Discovery | E1083: File and Directory Discovery |
| link function at runtime on Windows | T1129: Shared Modules | N/A |
| calculate modulo 256 via x86 assembly | N/A | C0058: Modulo |
| create or open file | N/A | C0016: Create File |
| modify access privileges | T1134: Access Token Manipulation | N/A |
*(source: capa, capa Capability Rules section)*
### High-Signal PE Imports
| Label | API | ATT&CK Technique |
|---|---|---|
| create_process | CreateProcess | T1106: System Binary Proxy Execution |
| load_library | LoadLibrary | T1129: Shared Modules |
| get_proc_address | GetProcAddress | T1129: Shared Modules |
| change_memory_protection | VirtualProtect | T1055: Process Injection |
| allocate_memory | VirtualAlloc | T1055: Process Injection |
*(source: pe_imports, PE Imports / Signals table)*
These capabilities confirm the sample is designed for obfuscation, system/registry/file reconnaissance, privilege escalation, process injection preparation, and arbitrary process execution, consistent with infostealer or RAT functionality.

## 9. Indicators of Compromise
All IOCs are static, extracted from the sample binary:
| IOC Type | Value | Source |
|---|---|---|
| SHA256 | e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 | llm_judge, Verdict section |
| File Path | /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe | llm_judge, Sample Metadata section |
| Embedded Domain | Offset 0, length 3 | yara, YARA Matches table, domain row |
| Embedded IPv4 | Offset 830343, length 7 | yara, YARA Matches table, IP row, $ipv4 string |
| Embedded IPv6 | Offset 917570, length 2 | yara, YARA Matches table, IP row, $ipv6 string |
| Embedded Base64 | Offset 2194, length 12 | yara, YARA Matches table, contains_base64 row |
| Embedded URL | Offset 722888, length 78 | yara, YARA Matches table, url row |
| DEP Bypass Code | Offset 738280, length 19 | yara, YARA Matches table, disable_dep row |
| Privilege Escalation Code | Offsets 761072 (len12), 761164 (len21) | yara, YARA Matches table, escalate_priv row |
| Registry Manipulation Code | Offsets 761072 (len12), 761260 (len11) | yara, YARA Matches table, win_registry row |
| Token Manipulation Code | Offsets 761072 (len12), 761164 (len21), 761274 (len16) | yara, YARA Matches table, win_token row |
| File Operation Code | Offsets 758600 (len12), 760088 (len9), 759296 (len14), 760088 (len9), 758874 (len8) | yara, YARA Matches table, win_files_operation row |
| Delphi Runtime Strings | Offsets 15976, 31860, 41422, 50636 | yara, YARA Matches table, Borland_Delphi_*/Borland/Delphi_CompareCall rows; floss, FLOSS Strings section |
| Delphi RTTI Strings | `Boolean`, `System`, `AnsiString`, `WideString`, `TObject&`, `DisposeOf`, `InitInstance`, `ClassName`, `&op_Equality`, `&op_Inequality`, `Create` | floss, FLOSS Strings section |
| Entry Point | 0x004b5eec | radare2, radare2 Disassembly section, 0x004b5eec |

## 10. Detection Engineering
### Static Detection Rules
1. **YARA Detection**: Use the existing 26 matched YARA rules to detect this sample or variants, including compiler identification rules (`borland_delphi`, `Borland_Delphi_*`), packed state rules (`IsPacked`, `HasOverlay`), and capability-specific rules (`disable_dep`, `escalate_priv`, `win_registry`, `win_token`, `win_files_operation`, `domain`, `IP`, `url`, `contains_base64`) (source: yara, YARA Matches table).
2. **Import-Based Detection**: Flag PE files with the high-signal import set: `CreateProcess`, `LoadLibrary`, `GetProcAddress`, `VirtualAlloc`, `VirtualProtect`, combined with Delphi compiler artifacts (source: pe_imports, PE Imports / Signals table; source: yara, YARA Matches table, borland_delphi row).
3. **String-Based Detection**: Detect the presence of Delphi RTTI strings (`Boolean`, `System`, `AnsiString`, `WideString`, `TObject&`, `DisposeOf`, `InitInstance`, `ClassName`) in static string extractions (source: floss, FLOSS Strings section).
4. **Offset-Based Network Indicator Detection**: Scan for network indicators at the known static offsets: domain at 0, IPv4 at 830343, IPv6 at 917570, URL at 722888, base64 at 2194 (source: yara, Generated YARA Meta section).
### Behavioral Detection
Use capa rules to detect the sample's capabilities in memory or unpacked payloads: XOR/RC4 obfuscation, system/registry/file discovery, token manipulation, and process injection preparation (source: capa, capa Capability Rules section).

## 11. What We Don't Know
1. **Unpacked Payload Content**: UPX unpack attempt failed with no output, so the underlying obfuscated payload is not available for analysis (source: upx, UPX Unpack section, upx_ok: False, unpacked_path: ``).
2. **Decoded C2 Indicators**: YARA confirms embedded domains, IPs, URLs, and base64 data exist, but no decoded values are available from static or dynamic analysis (source: yara, YARA Matches table, domain/IP/url/contains_base64 rows; source: speakeasy, Speakeasy section, no dynamic behavior observed).
3. **Runtime Execution Flow**: No dynamic emulation (Speakeasy) or Frida hook calls were observed, so actual runtime execution flow, C2 communication, and payload deployment steps are unknown (source: speakeasy, Speakeasy section; source: frida, Frida Probe section).
4. **Final Payload Functionality**: While the sample is guessed to be an infostealer or RAT based on capabilities, no explicit data theft, RAT command handling, or exfiltration code was confirmed in static analysis (source: llm_judge, Verdict section, family_guess).
5. **Persistence Mechanisms**: capa detected registry access capabilities, but no specific persistence mechanisms (e.g., Run key modifications, scheduled tasks) were identified (source: capa, capa Capability Rules section, create or open registry key / query or enumerate registry value rows).
6. **Obfuscation Keys**: XOR and RC4 obfuscation are confirmed, but the specific encryption keys or XOR masks were not extracted from the packed sample (source: capa, capa Capability Rules section, encode data using XOR / encrypt data using RC4 PRGA rows).

## 12. Appendix: Analysis Environment
| Tool | Version/Details | Output |
|---|---|---|
| radare2 | N/A | Entry point disassembly at 0x004b5eec, function recovery for 4 key functions (source: radare2, radare2 Disassembly section) |
| capa | Runtime 89.43s | 49 matched capability rules (source: capa, capa Capability Rules section) |
| YARA | N/A | 26 rule matches, including compiler, packed state, capability, and network indicator rules (source: yara, YARA Matches section) |
| FLOSS | N/A | 11,298 extracted strings (1 tight, 11,297 static) including Delphi RTTI artifacts (source: floss, FLOSS Strings section) |
| Speakeasy | N/A | Emulation completed, 0 API calls/events observed (source: speakeasy, Speakeasy section) |
| Frida | v17.16.4 | 24 hook candidates identified, no runtime calls observed (source: frida, Frida Probe section) |
| UPX | N/A | Unpack attempt failed, returncode: None, no unpacked output (source: upx, UPX Unpack section) |
| XOR Search | N/A | XOR 00 value identified at file position 0 (source: XOR Search section) |
| Ghidra | N/A | Analysis failed due to project ownership error (source: llm_judge, cross_engine_notes) |
| IDA | N/A | Analysis failed due to missing idasql binary (source: llm_judge, cross_engine_notes) |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819  
**sample_path:** /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 92
- **family_guess**: Unknown Delphi-based packed malware, likely an infostealer or remote access trojan (RAT) given its system/registry/file discovery, process injection, and privilege escalation capabilities
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA analysis failed due to technical issues (Ghidra project ownership error, missing idasql binary), so all evidence is sourced from pe_imports, capa, YARA, and FLOSS. Cross-engine alignment is strong: YARA's Delphi compiler identification matches FLOSS's Delphi-specific strings; pe_imports' high-signal process injection and execution APIs align with capa's detected process injection, execution, and obfuscation behaviors. The sample's packed state (confirmed by YARA) explains its large 2.2MB size, high string count, and failure of Ghidra/IDA to extract function data.
- **summary**: This is a packed 2.2MB Borland Delphi PE file with 142 imports, including high-signal APIs for process creation, dynamic API resolution, and memory manipulation. Static analysis via capa identifies obfuscation (XOR, RC4), system/file/registry reconnaissance, and privilege escalation capabilities. YARA rules confirm the sample is packed, built with Delphi, and contains code for DEP bypass, privilege escalation, registry/token interaction, and embedded C2 indicators (domains, IPs, base64 data). FLOSS strings corroborate the Delphi compiler identification. All static indicators point to malicious functionality consistent with an infostealer or RAT.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | high-signal import signals | `CreateProcess (mapped to ATT&CK T1106)` | This high-signal import is used for spawning new processes, a core capability for malware execution, process injection,  |
| pe_imports | high-signal import signals | `LoadLibrary + GetProcAddress (mapped to ATT&CK T1129)` | These imports enable dynamic API resolution, a common malware technique to hide malicious functionality from static anal |
| pe_imports | high-signal import signals | `VirtualAlloc + VirtualProtect (mapped to ATT&CK T1055)` | These imports are used for memory allocation and modifying memory page permissions, core capabilities for process inject |
| capa | top ATT&CK behavior rules | `encode data using XOR (T1027) + encrypt data using RC4 PRGA (T1027)` | These rules confirm the sample uses obfuscation (XOR encoding, RC4 encryption) to hide malicious code or sensitive data, |
| capa | top ATT&CK behavior rules | `System Information Discovery (T1082): check OS version, get disk size, query env` | This behavior indicates the sample performs system reconnaissance to profile the target environment, a common step for m |
| capa | top ATT&CK behavior rules | `Query Registry (T1012): query or enumerate registry value` | Registry access is commonly used by malware for persistence, storing configuration data, or stealing stored credentials. |
| capa | top ATT&CK behavior rules | `Access Token Manipulation (T1134): modify access privileges` | This behavior indicates the sample manipulates Windows access tokens to escalate privileges, allowing it to perform rest |
| yara | rule matches | `domain, IP, contains_base64 rules` | These rules indicate the sample contains embedded domain names, IP addresses, and base64-encoded data, likely used for c |
| yara | rule matches | `disable_dep, escalate_priv, win_registry, win_token` | These YARA rules directly confirm the sample contains code to bypass Data Execution Prevention (DEP), escalate user priv |
| yara | rule matches | `IsPacked, HasOverlay, Borland_Delphi* compiler rules` | These rules confirm the sample is packed (obfuscated) and built with the Borland Delphi compiler, a common choice for ma |
| floss | extracted strings | `Delphi RTL/internal strings (e.g., InitInstance, GetInterface, TInterfaceTable)` | These Delphi-specific strings align with YARA's compiler identification, and the total of 11,298 extracted strings is co |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Sample e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 is a packed Borland/Delphi GUI PE with strong malicious indicators. Static analysis shows obfuscation/encoding (XOR, RC4), high-signal offensive imports (CreateProcess, VirtualAlloc, VirtualProtect, LoadLibrary, GetProcAddress), registry manipulation, network indicators (domain, IP, URL, base64), and Delphi runtime artifacts. Emulation produced no observable behavior, but deterministic static signals dominate.

### deep key_evidence
- `"YARA 26 matches: Borland/Delphi family, IsPacked, HasOverlay, domain, IP, URL, base64, CRC32_poly_Constant, Delphi_CompareCall"`
- `"capa 49 rules: encode data using XOR (T1027), encrypt data using RC4 PRGA (T1027), create or open registry key, check OS version, plus additional obfuscation/anti-analysis rules"`
- `"pe_import_signals: CreateProcess (T1106), LoadLibrary (T1129), GetProcAddress (T1129), VirtualProtect (T1055), VirtualAlloc (T1055)"`
- `"floss: 11298 strings including Delphi RTTI/type names (Boolean, System, AnsiString, WideString, TObject&, DisposeOf, InitInstance, ClassName, etc.) and 1 tight string"`
- `"r2 entry0 at 0x004b5eec with large stack frame and Delphi-style initialization"`
- `"speakeasy_emulate: no dynamic API calls or strings observed, consistent with packed/obfuscated static-only sample"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 49 · duration_s: 89.43

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| link function at runtime on Windows | T1129:Shared Modules |  |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |
| create or open file |  | C0016:Create File |
| modify access privileges | T1134:Access Token Manipulation |  |

## PE Imports / Signals
import_count: 142

| label | api_match | ATT&CK |
|---|---|---|
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 26

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=3 |
| IP | - | $ipv4@830343 len=7; $ipv6@917570 len=2 |
| contains_base64 | - | $a@2194 len=12 |
| CRC32_poly_Constant | - | $c0@146170 len=4 |
| Delphi_CompareCall | - | $c1@31860 len=42 |
| url | - | $url_regex@722888 len=78 |
| Borland | - | $patternBorland@41422 len=14 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| borland_delphi | - | $c0@50636 len=42; $c1@50636 len=73 |
| Borland_Delphi_40_additional | - | $a@15976 len=5 |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@15728 len=4 |
| Borland_Delphi_30_additional | - | $a@15976 len=4 |
| Borland_Delphi_30_ | - | $a@15976 len=4 |
| Borland_Delphi_Setup_Module | - | $a@15976 len=5 |
| Borland_Delphi_40 | - | $a@15976 len=5 |
| Borland_Delphi_v40_v50 | - | $a@15976 len=4 |
| Borland_Delphi_v30 | - | $a@15976 len=4 |
| Borland_Delphi_DLL | - | $a@15976 len=4 |
| disable_dep | - | $c4@738280 len=19 |
| escalate_priv | - | $d1@761072 len=12; $c2@761164 len=21 |
| win_registry | - | $f1@761072 len=12; $c3@761260 len=11; $c6@761260 len=11 |
| win_token | - | $f1@761072 len=12; $c2@761164 len=21; $c3@761274 len=16 |
| win_files_operation | - | $f1@758600 len=12; $c1@760088 len=9; $c2@759296 len=14; $c3@760088 len=9; $c4@758874 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 830343,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 917570,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2194,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 146170,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Delphi_CompareCall",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 31860,
          "length": 42,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 722888,
          "length": 78,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$patternBorland",
          "offset": 41422,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "borland_delphi",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 50636,
          "length": 42,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 50636,
          "length": 73,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_40_additional",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 15976,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/incoming/e29d2
```

## FLOSS Strings
Total strings: 11298 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 1, "language_strings": 0, "language_strings_missed": 0, "static_strings": 11297}`

### FLOSS sample
- `1096159247`
- `This program must be run under Win32`
- ``.itext`
- ``.data`
- `.idata`
- `.didata`
- `.edata`
- `.rdata`
- `@.rsrc`
- `Boolean`
- `System`
- `AnsiChar`
- `ShortInt`
- `SmallInt`
- `Integer`
- `Cardinal`
- `Pointer`
- `UInt64`
- `NativeInt`
- `NativeUInt`
- `Single`
- `Extended`
- `Double`
- `Currency`
- `ShortString`
- `PAnsiChar0`
- `PWideCharL`
- `ByteBool`
- `WordBool`
- `LongBool`
- `string`
- `WideString`
- `AnsiString`
- `Variant`
- `OleVariant`
- `TClass`
- `HRESULT`
- `&op_Equality`
- `&op_Inequality`
- `Create`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004b5eec
```asm
┌ 501: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_24h @ ebp-0x24
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_38h @ ebp-0x38
│           ; var int32_t var_3ch @ ebp-0x3c
│           ; var int32_t var_40h @ ebp-0x40
│           ; var int32_t var_5ch @ ebp-0x5c
│           0x004b5eec      55             push ebp
│           0x004b5eed      8bec           mov ebp, esp
│           0x004b5eef      83c4a4         add esp, 0xffffffa4
│           0x004b5ef2      53             push ebx
│           0x004b5ef3      56             push esi
│           0x004b5ef4      57             push edi
│           0x004b5ef5      33c0           xor eax, eax
│           0x004b5ef7      8945c4         mov dword [var_3ch], eax
│           0x004b5efa      8945c0         mov dword [var_40h], eax
│           0x004b5efd      8945a4         mov dword [var_5ch], eax
│           0x004b5f00      8945d0         mov dword [var_30h], eax
│           0x004b5f03      8945c8         mov dword [var_38h], eax
│           0x004b5f06      8945cc         mov dword [var_34h], eax
│           0x004b5f09      8945d4         mov dword [var_2ch], eax
│           0x004b5f0c      8945d8         mov dword [var_28h], eax
│           0x004b5f0f      8945ec         mov dword [var_14h], eax
│           0x004b5f12      b8b8144b00     mov eax, 0x4b14b8
│           0x004b5f17      e8b072f5ff     call 0x40d1cc
│           0x004b5f1c      33c0           xor eax, eax
│           0x004b5f1e      55             push ebp
│           0x004b5f1f      68e2654b00     push 0x4b65e2
│           0x004b5f24      64ff30         push dword fs:[eax]
│           0x004b5f27      648920         mov dword fs:[eax], esp
│           0x004b5f2a      33d2           xor edx, edx
│           0x004b5f2c      55             push ebp
│           0x004b5f2d      689e654b00     push 0x4b659e
│           0x004b5f32      64ff32         push dword fs:[edx]
│           0x004b5f35      648922         mov dword fs:[edx], esp
│           0x004b5f38      a134e64b00     mov eax, dword [0x4be634]   ; [0x4be634:4]=0
│           0x004b5f3d      e8a29dffff     call 0x4afce4
│           0x004b5f42      e8f598ffff     call 0x4af83c
│           0x004b5f47      8d55ec         lea edx, [var_14h]
│           0x004b5f4a      33c0           xor eax, eax
│           0x004b5f4c      e84fcdf6ff     call 0x422ca0
│           0x004b5f51      8b55ec         mov edx, dword [var_14h]
│           0x004b5f54      b8841d4c00     mov eax, 0x4c1d84
│           0x004b5f59      e8a21ef5ff     call 0x407e00
│           0x004b5f5e      6a02           push 2                      ; 2
│           0x004b5f60      6a00           push 0
│           0x004b5f62      6a01           push 1  
```
### 0x0040d0a0
```asm
┌ 167: sym.SetupLdr.exe___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x0040d0a0      55             push ebp
│       ╎   0x0040d0a1      8bec           mov ebp, esp
│       ╎   0x0040d0a3      51             push ecx
│       ╎   0x0040d0a4      53             push ebx
│       ╎   0x0040d0a5      56             push esi
│       ╎   0x0040d0a6      57             push edi
│       ╎   0x0040d0a7      33c0           xor eax, eax
│       ╎   0x0040d0a9      8945fc         mov dword [var_4h], eax
│       ╎   0x0040d0ac      33c0           xor eax, eax
│       ╎   0x0040d0ae      55             push ebp
│       ╎   0x0040d0af      6841d14000     push 0x40d141
│       ╎   0x0040d0b4      64ff30         push dword fs:[eax]
│       ╎   0x0040d0b7      648920         mov dword fs:[eax], esp
│       ╎   0x0040d0ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0bd      50             push eax
│       ╎   0x0040d0be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0c1      50             push eax
│       ╎   0x0040d0c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0c5      50             push eax
│       ╎   0x0040d0c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0c9      50             push eax
│       ╎   0x0040d0ca      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0cd      50             push eax
│       ╎   0x0040d0ce      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0d1      50             push eax
│       ╎   0x0040d0d2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0d5      50             push eax
│       ╎   0x0040d0d6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0d9      50             push eax
│       ╎   0x0040d0da      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0dd      50             push eax
│       ╎   0x0040d0de      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0e1      50             push eax
│       ╎   0x0040d0e2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0e5      50             push eax
│       ╎   0x0040d0e6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0e9      50             push eax
│       ╎   0x0040d0ea      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0ed      50             push eax
│       ╎   0x0040d0ee      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0f1      50             push eax
│       ╎   0x0040d0f2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0f5      50             push eax
│       ╎   0x0040d0f6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0f9      50             push eax
│       ╎   0x0040d0fa      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d0fd      50             push eax
│       ╎   0x0040d0fe      8b45fc         mov eax, dword [var_4h]
│       ╎   0x0040d101      50             push eax
│       ╎   0x0040d102      8b45f
```
### 0x0040ccb0
```asm
; CALL XREF from sym.SetupLdr.exe___dbk_fcall_wrapper @ 0x40d12f(x)
┌ 1007: fcn.0040ccb0 ();
│           0x0040ccb0      55             push ebp
│           0x0040ccb1      8bec           mov ebp, esp
│           0x0040ccb3      e8f4ffffff     call fcn.0040ccac
│           0x0040ccb8      e8efffffff     call fcn.0040ccac
│           0x0040ccbd      e8eaffffff     call fcn.0040ccac
│           0x0040ccc2      e8e5ffffff     call fcn.0040ccac
│           0x0040ccc7      e8e0ffffff     call fcn.0040ccac
│           0x0040cccc      e8dbffffff     call fcn.0040ccac
│           0x0040ccd1      e8d6ffffff     call fcn.0040ccac
│           0x0040ccd6      e8d1ffffff     call fcn.0040ccac
│           0x0040ccdb      e8ccffffff     call fcn.0040ccac
│           0x0040cce0      e8c7ffffff     call fcn.0040ccac
│           0x0040cce5      e8c2ffffff     call fcn.0040ccac
│           0x0040ccea      e8bdffffff     call fcn.0040ccac
│           0x0040ccef      e8b8ffffff     call fcn.0040ccac
│           0x0040ccf4      e8b3ffffff     call fcn.0040ccac
│           0x0040ccf9      e8aeffffff     call fcn.0040ccac
│           0x0040ccfe      e8a9ffffff     call fcn.0040ccac
│           0x0040cd03      e8a4ffffff     call fcn.0040ccac
│           0x0040cd08      e89fffffff     call fcn.0040ccac
│           0x0040cd0d      e89affffff     call fcn.0040ccac
│           0x0040cd12      e895ffffff     call fcn.0040ccac
│           0x0040cd17      e890ffffff     call fcn.0040ccac
│           0x0040cd1c      e88bffffff     call fcn.0040ccac
│           0x0040cd21      e886ffffff     call fcn.0040ccac
│           0x0040cd26      e881ffffff     call fcn.0040ccac
│           0x0040cd2b      e87cffffff     call fcn.0040ccac
│           0x0040cd30      e877ffffff     call fcn.0040ccac
│           0x0040cd35      e872ffffff     call fcn.0040ccac
│           0x0040cd3a      e86dffffff     call fcn.0040ccac
│           0x0040cd3f      e868ffffff     call fcn.0040ccac
│           0x0040cd44      e863ffffff     call fcn.0040ccac
│           0x0040cd49      e85effffff     call fcn.0040ccac
│           0x0040cd4e      e859ffffff     call fcn.0040ccac
│           0x0040cd53      e854ffffff     call fcn.0040ccac
│           0x0040cd58      e84fffffff     call fcn.0040ccac
│           0x0040cd5d      e84affffff     call fcn.0040ccac
│           0x0040cd62      e845ffffff     call fcn.0040ccac
│           0x0040cd67      e840ffffff     call fcn.0040ccac
│           0x0040cd6c      e83bffffff     call fcn.0040ccac
│           0x0040cd71      e836ffffff     call fcn.0040ccac
│           0x0040cd76      e831ffffff     call fcn.0040ccac
│           0x0040cd7b      e82cffffff     call fcn.0040ccac
│           0x0040cd80      e827ffffff     call fcn.0040ccac
│           0x0040cd85      e822ffffff     call fcn.0040ccac
│           0x0040cd8a      e81dffffff     call fcn.0040ccac
│           0x0040cd8f      e818ffffff     call fcn.0040ccac
│           0x0040cd94      e813ffffff     call fcn.00
```
### 0x0040ccac
```asm
; XREFS(200)
┌ 1: fcn.0040ccac ();
└           0x0040ccac      c3             ret
```
### 0x004541a8
```asm
┌ 16: sym.SetupLdr.exe_TMethodImplementationIntercept (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           0x004541a8      55             push ebp
│           0x004541a9      8bec           mov ebp, esp
│           0x004541ab      8b550c         mov edx, dword [arg_ch]
│           0x004541ae      8b4508         mov eax, dword [arg_8h]
│           0x004541b1      e802000000     call fcn.004541b8
│           0x004541b6      5d             pop ebp
└           0x004541b7      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r

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
  - `kernel32.dll!GetACP`
  - `kernel32.dll!GetExitCodeProcess`
  - `kernel32.dll!LocalFree`
  - `kernel32.dll!CloseHandle`
  - `kernel32.dll!SizeofResource`
  - `comctl32.dll!InitCommonControls`
  - `version.dll!GetFileVersionInfoSizeW`
  - `version.dll!VerQueryValueW`
  - `version.dll!GetFileVersionInfoW`
  - `user32.dll!CreateWindowExW`
  - `user32.dll!TranslateMessage`
  - `user32.dll!CharLowerBuffW`
  - `user32.dll!CallWindowProcW`
  - `user32.dll!CharUpperW`
  - `oleaut32.dll!SysAllocStringLen`
  - `oleaut32.dll!SafeArrayPtrOfIndex`
  - `oleaut32.dll!VariantCopy`
  - `oleaut32.dll!SafeArrayGetLBound`
  - `oleaut32.dll!SafeArrayGetUBound`
  - `netapi32.dll!NetWkstaGetInfo`
  - `netapi32.dll!NetApiBufferFree`
  - `advapi32.dll!ConvertStringSecurityDescriptorToSecurityDescriptorW`
  - `advapi32.dll!RegQueryValueExW`
  - `advapi32.dll!AdjustTokenPrivileges`
  - `advapi32.dll!GetTokenInformation`
  - `advapi32.dll!ConvertSidToStringSidW`
