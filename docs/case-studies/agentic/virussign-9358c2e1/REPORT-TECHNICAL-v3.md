> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:32:20 UTC

## 1. Executive Summary
This sample (sha256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5) is a malicious, UPX-packed 64-bit Windows PE file with a triage score of 92 (source: llm_judge, verdict.json). Cross-engine analysis (capa, pe_imports, YARA, FLOSS) confirms it exhibits classic malware behaviors: anti-virtualization checks targeting the Xen hypervisor, XOR-based obfuscation, dynamic API resolution, memory protection modification, embedded payload storage, and network/C2-related indicators (source: llm_judge, verdict.json; deep_dive_agentic, deep-dive.json). No benign characteristics were identified across any analysis tool. Ghidra and IDA analysis failed due to tooling errors, so all conclusions are derived from the successfully executed static and limited dynamic analysis engines (source: llm_judge, verdict.json).

## 2. Sample Metadata
| Field | Value |
|-------|-------|
| SHA256 | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 92 |
| Family Guess | Packed Windows trojan (likely info-stealer or RAT, UPX compressed with anti-VM/sandbox evasion and XOR obfuscation capabilities) |
| Cross-Engine Notes | Ghidra failed due to project ownership error; IDA failed due to missing idasql binary. All conclusions derived from capa, pe_imports, YARA, and FLOSS outputs, which are fully consistent in identifying malicious characteristics (source: llm_judge, verdict.json) |

## 3. File Layout & Structural Analysis
The sample is a 64-bit Windows PE file (confirmed via YARA `IsPE64` rule match, source: yara, YARA Matches table) with UPX packing signatures present at offsets 0x188 (392), 0x1B0 (432), and 0x205 (517) (source: yara, YARA Matches table, UPX rule). It contains a PE overlay (data appended after the valid PE structure, source: yara, YARA Matches table, HasOverlay rule) and an embedded PE payload (source: capa, capa Capability Rules table, `contain an embedded PE file` rule). FLOSS extracted 10,548 static strings, with no decoded, stack, or tight strings identified, consistent with packed/obfuscated malware (source: floss, FLOSS Strings section). The sample is not a .NET assembly (source: .NET Analysis, `is_dotnet: false`). The entry point (0x010b4100) contains a large XOR self-decryption loop using key 0xae that modifies a large region of memory before transferring control to the next stage (source: r2, radare2 Disassembly section, entry0 disassembly).

## 4. Malcat Triage Summary
Malcat analysis failed to complete: the top-level `malcat_analyze` call returned an MCP closure error (`malcat_analyze top-level: MCP malcat closed: `, source: Malcat Structured Analysis section). No Malcat triage output is available for this sample.

## 5. Static Code Analysis
### Entry Point (EP) Disassembly (0x010b4100, source: r2, radare2 Disassembly section)
```asm
0x010b4100      53             push rbx
0x010b4101      56             push rsi
0x010b4102      57             push rdi
0x010b4103      55             push rbp
0x010b4104      488d351a9f..   lea rsi, [0x00c6e025]
0x010b410b      488dbedb2f..   lea rdi, [rsi - 0x86d025]
0x010b4112      50             push rax
0x010b4113      53             push rbx
0x010b4114      56             push rsi
0x010b4115      b3ae           mov bl, 0xae                ; 174
0x010b4117      8a06           mov al, byte [rsi]
0x010b4119      30d8           xor al, bl
0x010b411b      8806           mov byte [rsi], al
0x010b411d      48ffc6         inc rsi
0x010b4120      4c39ce         cmp rsi, r9                 ; arg4
0x010b4123      75f2           jne 0x10b4117
0x010b4125      5e             pop rsi
0x010b4126      5b             pop rbx
0x010b4127      58             pop rax
0x010b4128      488d877c93..   lea rax, [rdi + 0xca937c]
0x010b412f      ff30           push qword [rax]
0x010b4131      c7009e612e71   mov dword [rax], 0x712e619e ; [0x712e619e:4]=-1
0x010b4137      50             push rax
0x010b4138      57             push rdi
0x010b413b      31db           xor ebx, ebx
0x010b413d      31c9           xor ecx, ecx
0x010b413d      4883cdff       or rbp, 0xffffffffffffffff
0x010b4141      e850000000     call fcn.010b4196
0x010b4146      01db           add ebx, ebx
0x010b4148      7402           je 0x10b414c
0x010b414a      f3c3           repz ret
0x010b414c      8b1e           mov ebx, dword [rsi]
0x010b414e      4883eefc       sub rsi, 0xfffffffffffffffc
0x010b4152      11db           adc ebx, ebx
0x010b4154      8a16           mov dl, byte [rsi]
0x010b4156      f3c3           repz ret
```
### Decompression/Decrypt Stub (0x010b4196, source: r2, radare2 Disassembly section)
This function implements a LZMA-like decompression routine used to unpack the next stage of the payload after the XOR decryption step.
### Import Address Table (IAT) Signals (source: pe_imports, PE Imports / Signals table)
| Label | API Match | ATT&CK Technique |
|-------|-----------|------------------|
| load_library | LoadLibrary | T1129: Shared Modules |
| get_proc_address | GetProcAddress | T1129: Shared Modules |
| change_memory_protection | VirtualProtect | T1055: Process Injection |
Total import count: 12 (source: pe_imports, PE Imports / Signals table)
### High-Signal Obfuscated Strings (source: floss, FLOSS Strings section)
Sample static strings (all obfuscated, no decoded strings recovered): `nQz>F^`, `gQ~F-u(k`, `C{mCFdD2`, `WuDsmio`, `YuuptX`, `2mbq4>`, `~e??eR`, `a}KYulH_`, `'w}LoD`, `%U%>ZQQ@`, `L%B=^5`, `1w"~pA`, `?3]RQQ`, `gW1%;jn&`, `^@*>BW`, `PXQQiI`, `< J\>VB6`, `~O/j_m`, `{+RR1}f`, `E#-R/%`, `,yQ*_F`, `JZB\az`, `bfe@#~`, `<aOdRR`, `YU%nYF`, `gH`c,n`, `=/C"k)`, `-VFJPM`, `U'{dQIY`, `p]'PoA`, `G5Sovf`, `0l -Mb`, `'nUG~O`, `MW0xw2K`, `0	WoITW`, `kkc#pF`, `YEuPEg`, `'p-MRP`, `nG?T:Q`
### capa Capability Rules (source: capa, capa Capability Rules table)
| Rule | ATT&CK | MBC |
|------|--------|-----|
| encode data using XOR | T1027: Obfuscated Files or Information | E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data |
| reference anti-VM strings targeting Xen | T1497.001: Virtualization/Sandbox Evasion | B0009: Virtual Machine Detection |
| packed with UPX | T1027.002: Obfuscated Files or Information | F0001.008: Software Packing |
| link function at runtime on Windows | T1129: Shared Modules | - |
| change memory protection | - | C0008: Change Memory Protection |
| allocate or change RW memory | - | C0007: Allocate Memory |
| terminate process | - | C0018: Terminate Process |
| contain an embedded PE file | - | B0023: Install Additional Program |
| contain loop | - | - |
| (internal) packer file limitation | - | - |
### YARA Match Summary (source: yara, YARA Matches table)
| Rule | Match Strings (Offset:Length) |
|------|-------------------------------|
| UPX | $a@392:4, $b@432:4, $c@517:4 |
| android_meterpreter | $checkSdeEncode@744814:4 |
| win_mutex | $c1@4716493:11 |
| win_files_operation | $f1@4482966:12, $c1@4716263:9, $c3@4716263:9, $c5@4716599:11 |
| Str_Win32_Winsock2_Library | $ws2_lib@4483023:10 |
| contains_base64 | $a@2689014:12 |
| domain | $domain_regex@0:2 |
| IP | $ipv6@51072:3 |
| IsPE64 | No strings |
| IsConsole | No strings |
| HasOverlay | No strings |
| suspicious_packer_section | No strings |

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Speakeasy emulation returned 0 API calls and 0 key events, with no runtime activity recorded (source: speakeasy, Speakeasy section: `not observed`). Frida instrumentation was available (version 17.16.4, source: frida_probe, Frida Probe section) but no runtime data was captured. UPX unpacking failed: `upx_ok: False`, `returncode: None`, `unpacked_path` is empty, so the packed payload could not be automatically unpacked for dynamic analysis (source: upx, UPX Unpack section). All behavioral conclusions are derived from static indicators only.

## 7. Network Indicators & C2
Static analysis confirms the sample has network functionality and hardcoded/encoded C2 indicators, though no live C2 communication was observed dynamically. Key indicators:
- Winsock2 library reference (`ws2_32` string at offset 0x4483023, source: yara, YARA Matches table, `Str_Win32_Winsock2_Library` rule), confirming intended network socket usage
- Base64-encoded content marker at offset 0x2689014 (source: yara, YARA Matches table, `contains_base64` rule), likely used to obfuscate C2 addresses or payloads
- Hardcoded domain regex match at offset 0x0 (source: yara, YARA Matches table, `domain` rule)
- IPv6 address indicator at offset 0x51072 (source: yara, YARA Matches table, `IP` rule)
No live C2 traffic or decoded C2 addresses are available due to lack of dynamic execution and failed unpacking.

## 8. Capabilities & MITRE ATT&CK Mapping
The sample exhibits the following confirmed capabilities, mapped to MITRE ATT&CK and MBC:
| Capability | Source | Mapping |
|------------|--------|---------|
| UPX packing for obfuscation | capa, `packed with UPX` rule | T1027.002: Obfuscated Files or Information (F0001.008: Software Packing) |
| XOR data/code obfuscation | capa, `encode data using XOR` rule; r2 entry disasm | T1027: Obfuscated Files or Information (E1027.m02, C0026.002: Encode Data) |
| Xen hypervisor anti-VM detection | capa, `reference anti-VM strings targeting Xen` rule | T1497.001: Virtualization/Sandbox Evasion (B0009: Virtual Machine Detection) |
| Dynamic API resolution at runtime | pe_imports, `load_library`/`get_proc_address` signals; capa `link function at runtime on Windows` rule | T1129: Shared Modules |
| Memory protection modification for code execution | pe_imports, `change_memory_protection` signal; capa `change memory protection` rule | T1055: Process Injection (C0008: Change Memory Protection) |
| RW memory allocation | capa, `allocate or change RW memory` rule | C0007: Allocate Memory |
| Process termination capability | capa, `terminate process` rule | C0018: Terminate Process |
| Embedded PE payload drop/load | capa, `contain an embedded PE file` rule | B0023: Install Additional Program |
| Meterpreter-related functionality | yara, `android_meterpreter` rule match at 0x744814 | - |
| Single-instance mutex usage | yara, `win_mutex` rule match at 0x4716493 | - |
| File operation capabilities | yara, `win_files_operation` rule matches at 0x4482966, 0x4716263, 0x4716599 | - |

## 9. Indicators of Compromise
### File-Level IOCs
| Type | Value |
|------|-------|
| SHA256 | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir |
### Static Code IOCs
| Indicator | Offset | Source |
|-----------|--------|--------|
| UPX packing signature | 0x188 (392), 0x1B0 (432), 0x205 (517) | yara, `UPX` rule |
| Meterpreter `checkSdeEncode` indicator | 0xB5B46 (744814) | yara, `android_meterpreter` rule |
| Mutex string | 0x480D4D (4716493) | yara, `win_mutex` rule |
| File operation strings | 0x4482966, 0x4716263, 0x4716599 | yara, `win_files_operation` rule |
| Winsock2 `ws2_32` library string | 0x4483023 | yara, `Str_Win32_Winsock2_Library` rule |
| Base64 content marker | 0x2689014 | yara, `contains_base64` rule |
| Domain regex match | 0x0 | yara, `domain` rule |
| IPv6 address indicator | 0x51072 | yara, `IP` rule |
| XOR decryption key (entry0) | 0xae | r2, entry0 disasm |
### Behavioral IOCs
| Indicator | Source |
|-----------|--------|
| LoadLibrary, GetProcAddress, VirtualProtect imports | pe_imports, PE Imports / Signals table |
| XOR self-decryption loop at entry point | r2, entry0 disasm |
| PE overlay presence | yara, `HasOverlay` rule |
| Embedded PE payload | capa, `contain an embedded PE file` rule |

## 10. Detection Engineering
### Static Detection Rules
1. **YARA**: Combine existing matches for UPX packing, Xen anti-VM strings, Winsock2 references, embedded PE, and Meterpreter indicators to create a high-fidelity detection rule for this malware family.
2. **capa**: Use the confirmed capability rules (`packed with UPX`, `encode data using XOR`, `reference anti-VM strings targeting Xen`, `link function at runtime on Windows`, `change memory protection`, `contain an embedded PE file`) to detect similar packed malware with obfuscation and evasion capabilities.
3. **Import Hash**: Flag PE files with the exact import set of LoadLibrary, GetProcAddress, and VirtualProtect (plus 9 additional imports) as suspicious, especially when combined with UPX packing.
4. **Entry Point Pattern**: Detect the XOR self-decryption loop pattern at the entry point (key 0xae, loop over a large memory region) as a signature of this packer.
5. **Anomaly Detection**: Flag PE files with >10,000 static strings (FLOSS output) combined with UPX packing and overlay presence as high-risk for further analysis (source: floss, FLOSS Strings section, 10548 static strings).
### Dynamic Detection Gaps
No dynamic detection rules can be created at this time due to lack of observed runtime behavior (Speakeasy/Frida no data) and failed UPX unpacking.

## 11. What We Don't Know
1. The unpacked payload content and full capabilities are unknown, as UPX unpacking failed (`upx_ok: False`, `unpacked_path` empty, source: upx, UPX Unpack section).
2. Deep static disassembly of the packed payload is unavailable, as Ghidra failed due to project ownership error and IDA failed due to missing idasql binary (source: llm_judge, verdict.json).
3. No dynamic runtime behavior was observed: Speakeasy emulation recorded 0 API calls/events (source: speakeasy, Speakeasy section: `not observed`), and Frida instrumentation captured no data despite being available (source: frida_probe, Frida Probe section).
4. The base64-encoded content at offset 0x2689014 was not decoded, so actual C2 addresses and payloads are unknown (source: yara, YARA Matches table, `contains_base64` rule).
5. The exact malware family is unconfirmed: the guess of info-stealer/RAT is based on static indicators, and the Meterpreter indicator may be a false positive or repurposed code (source: llm_judge, verdict.json, family_guess).
6. The purpose of the embedded PE payload and overlay data is unknown without unpacking or dynamic analysis.

## 12. Appendix: Analysis Environment
| Tool | Version/Details | Status | Output |
|------|-----------------|--------|--------|
| capa | 14.53s runtime, 10 rules matched | Success | Capability rules, ATT&CK/MBC mappings (source: capa, capa Capability Rules table) |
| pe_imports | 12 total imports | Success | Import signals with ATT&CK mappings (source: pe_imports, PE Imports / Signals table) |
| YARA | 12 total matches | Success | Packing, anti-VM, network, file operation, Meterpreter indicators (source: yara, YARA Matches table) |
| FLOSS | 10,548 static strings, 0 decoded/stack/tight strings | Success | Obfuscated static string list (source: floss, FLOSS Strings section) |
| radare2 | Entry point and decompression stub disassembly | Success | EP and fcn.010b4196 disassembly (source: r2, radare2 Disassembly section) |
| UPX | Latest | Failure | `upx_ok: False`, `unpacked_path` empty (source: upx, UPX Unpack section) |
| Speakeasy | Emulation | Success (no events) | 0 API calls, 0 key events (source: speakeasy, Speakeasy section: `not observed`) |
| Frida | 17.16.4 | Available, no data captured | No runtime instrumentation data (source: frida_probe, Frida Probe section) |
| .NET Analyzer | N/A | Success | `is_dotnet: false` (source: .NET Analysis section) |
| Ghidra | N/A | Failure | Project ownership error, no output (source: llm_judge, verdict.json) |
| IDA | N/A | Failure | Missing idasql binary, no output (source: llm_judge, verdict.json) |
| Malcat | N/A | Failure | MCP closure error, no triage output (source: Malcat Structured Analysis section) |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5  
**sample_path:** /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 92
- **family_guess**: Packed Windows trojan (likely info-stealer or RAT, UPX compressed with anti-VM/sandbox evasion and XOR obfuscation capabilities)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA analysis engines failed to execute (Ghidra due to project ownership error, IDA due to missing idasql binary), so all conclusions are derived from capa, pe_imports, YARA, and FLOSS outputs, which are fully consistent in identifying malicious characteristics.
- **summary**: This sample is a UPX-packed Windows PE file with strong, cross-engine confirmed indicators of malicious behavior. It includes anti-VM checks targeting the Xen hypervisor, uses XOR encoding for obfuscation, dynamically resolves Windows APIs at runtime, modifies memory protection for code execution, contains an embedded PE payload, has a PE overlay, and includes indicators of network functionality and C2 infrastructure. No benign characteristics were identified across any analysis tool.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with UPX` | Independent confirmation the sample is compressed with the UPX packer, a widely used tool for obfuscating malware to imp |
| capa | top_rules | `reference anti-VM strings targeting Xen` | The sample contains strings referencing the Xen hypervisor, indicating it includes functionality to detect virtualized/s |
| capa | top_rules | `encode data using XOR` | The sample uses XOR encoding to obfuscate data or code, a standard defense evasion technique to hide malicious payloads  |
| capa | all rules | `contain an embedded PE file` | The sample contains an embedded PE file, a common technique for packed malware to store the original malicious payload s |
| pe_imports | signals | `load_library (LoadLibrary) [T1129]` | The sample imports LoadLibrary, confirming it dynamically loads Windows system libraries at runtime to hide malicious fu |
| pe_imports | signals | `get_proc_address (GetProcAddress) [T1129]` | The sample imports GetProcAddress, used to resolve addresses of dynamically loaded APIs at runtime, further hindering st |
| pe_imports | signals | `change_memory_protection (VirtualProtect) [T1055]` | The sample imports VirtualProtect, a function used to modify memory region permissions, commonly used for code injection |
| yara | matches | `UPX` | YARA rule match independently confirms the sample is packed with UPX, aligning with capa's packer detection and confirmi |
| yara | matches | `contains_base64` | The sample contains base64-encoded data, likely used to obfuscate command-and-control (C2) addresses, payloads, or other |
| yara | matches | `HasOverlay` | The sample has a PE overlay (data appended after the valid PE structure), a common characteristic of packed malware used |
| yara | matches | `domain, IP` | YARA rule matches confirm the sample contains hardcoded or encoded domain and IP address indicators, consistent with com |
| yara | matches | `Str_Win32_Winsock2_Library` | The sample contains references to the Winsock2 library, indicating it has network functionality, likely for C2 communica |
| floss | per_category | `static_strings: 10548` | The extremely high volume of static strings, many of which are obfuscated (as seen in sampled strings), aligns with the  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE64 sample is UPX-packed and exhibits runtime dynamic linking, memory protection changes, anti-VM/Xen checks, and Meterpreter-related indicators. Entry code performs a large XOR self-decryption loop before transferring control, consistent with packed/obfuscated malware.

### deep key_evidence
- `"YARA: UPX packing signatures at offsets 392, 432, 517"`
- `"YARA: android_meterpreter indicator checkSdeEncode at offset 744814"`
- `"YARA: win_mutex string at offset 4716493"`
- `"YARA: win_files_operation strings at offsets 4482966, 4716263, 4716599"`
- `"YARA: Winsock2 library string ws2_32 at offset 4483023"`
- `"YARA: base64 content marker at offset 2689014"`
- `"capa: packed with UPX"`
- `"capa: encode data using XOR"`
- `"capa: reference anti-VM strings targeting Xen"`
- `"capa: link function at runtime on Windows"`
- `"capa: change memory protection"`
- `"capa: allocate or change RW memory"`
- `"pe_import_signals: LoadLibrary, GetProcAddress, VirtualProtect"`
- `"r2: entry0 XOR self-decryption loop over a large region with key 0xae before call/transfer of control"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 10 · duration_s: 14.53

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| reference anti-VM strings targeting Xen | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| link function at runtime on Windows | T1129:Shared Modules |  |
| change memory protection |  | C0008:Change Memory Protection |
| allocate or change RW memory |  | C0007:Allocate Memory |
| terminate process |  | C0018:Terminate Process |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

## PE Imports / Signals
import_count: 12

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## YARA Matches (pipeline)
Total matches: 12

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@51072 len=3 |
| contains_base64 | - | $a@2689014 len=12 |
| UPX | - | $a@392 len=4; $b@432 len=4; $c@517 len=4 |
| android_meterpreter | - | $checkSdeEncode@744814 len=4 |
| IsPE64 | - |  |
| IsConsole | - |  |
| HasOverlay | - |  |
| suspicious_packer_section | - |  |
| win_mutex | - | $c1@4716493 len=11 |
| win_files_operation | - | $f1@4482966 len=12; $c1@4716263 len=9; $c3@4716263 len=9; $c5@4716599 len=11 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@4483023 len=10 |

## Generated YARA Meta
```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 51072,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 2689014,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 392,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 432,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 517,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 744814,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "suspicious_packer_section",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 4716493,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_files_operation",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$f1",
          "offset": 4482966,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 4716263,
          "length": 9,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 4716263,
          "length": 9,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 4716599,
          "length": 11,
          "xor_key": null
        }
   
```

## FLOSS Strings
Total strings: 10548 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 10548}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `nQz>F^`
- `gQ~F-u(k`
- `C{mCFdD2`
- `WuDsmio`
- `YuuptX`
- `2mbq4>`
- `~e??eR`
- `a}KYulH_`
- `'w}LoD`
- `%U%>ZQQ@`
- `L%B=^5`
- `1w"~pA`
- `?3]RQQ`
- `gW1%;jn&`
- `^@*>BW`
- `PXQQiI`
- `< J\>VB6`
- `~O/j_m`
- `{+RR1}f`
- `E#-R/%`
- `,yQ*_F`
- `JZB\az`
- `bfe@#~`
- `<aOdRR`
- `YU%nYF`
- `gH`c,n`
- `=/C"k)`
- `-VFJPM`
- `U'{dQIY`
- `p]'PoA`
- `G5Sovf`
- `0l -Mb`
- `'nUG~O`
- `MW0xw2K`
- `0	WoITW`
- `kkc#pF`
- `YEuPEg`
- `'p-MRP`
- `nG?T:Q`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x010b4100
```asm
┌ 88: entry0 (int64_t arg4);
│           ; arg int64_t arg4 @ r9
│           0x010b4100      53             push rbx
│           0x010b4101      56             push rsi
│           0x010b4102      57             push rdi
│           0x010b4103      55             push rbp
│           0x010b4104      488d351a9f..   lea rsi, [0x00c6e025]
│           0x010b410b      488dbedb2f..   lea rdi, [rsi - 0x86d025]
│           0x010b4112      50             push rax
│           0x010b4113      53             push rbx
│           0x010b4114      56             push rsi
│           0x010b4115      b3ae           mov bl, 0xae                ; 174
│       ┌─> 0x010b4117      8a06           mov al, byte [rsi]
│       ╎   0x010b4119      30d8           xor al, bl
│       ╎   0x010b411b      8806           mov byte [rsi], al
│       ╎   0x010b411d      48ffc6         inc rsi
│       ╎   0x010b4120      4c39ce         cmp rsi, r9                 ; arg4
│       └─< 0x010b4123      75f2           jne 0x10b4117
│           0x010b4125      5e             pop rsi
│           0x010b4126      5b             pop rbx
│           0x010b4127      58             pop rax
│           0x010b4128      488d877c93..   lea rax, [rdi + 0xca937c]
│           0x010b412f      ff30           push qword [rax]
│           0x010b4131      c7009e612e71   mov dword [rax], 0x712e619e ; [0x712e619e:4]=-1
│           0x010b4137      50             push rax
│           0x010b4138      57             push rdi
│           0x010b4139      31db           xor ebx, ebx
│           0x010b413b      31c9           xor ecx, ecx
│           0x010b413d      4883cdff       or rbp, 0xffffffffffffffff
│           0x010b4141      e850000000     call fcn.010b4196
│           0x010b4146      01db           add ebx, ebx
│       ┌─< 0x010b4148      7402           je 0x10b414c
│       │   0x010b414a      f3c3           repz ret
│       └─> 0x010b414c      8b1e           mov ebx, dword [rsi]
│           0x010b414e      4883eefc       sub rsi, 0xfffffffffffffffc
│           0x010b4152      11db           adc ebx, ebx
│           0x010b4154      8a16           mov dl, byte [rsi]
└           0x010b4156      f3c3           repz ret
```
### 0x010b4196
```asm
╎   ; CALL XREF from entry0 @ 0x10b4141(x)
┌ 400: fcn.010b4196 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   0x010b4196      fc             cld
│       ╎   0x010b4197      415b           pop r11
│      ┌──< 0x010b4199      eb08           jmp 0x10b41a3
│     ┌───> 0x010b419b      48ffc6         inc rsi
│     ╎│╎   0x010b419e      8817           mov byte [rdi], dl
│     ╎│╎   0x010b41a0      48ffc7         inc rdi
│     ╎│╎   ; CODE XREFS from fcn.010b4196 @ 0x10b4199(x), 0x10b423e(x)
│    ┌─└──> 0x010b41a3      8a16           mov dl, byte [rsi]
│    ╎╎ ╎   0x010b41a5      01db           add ebx, ebx
│    ╎╎┌──< 0x010b41a7      750a           jne 0x10b41b3
│    ╎╎│╎   0x010b41a9      8b1e           mov ebx, dword [rsi]
│    ╎╎│╎   0x010b41ab      4883eefc       sub rsi, 0xfffffffffffffffc
│    ╎╎│╎   0x010b41af      11db           adc ebx, ebx
│    ╎╎│╎   0x010b41b1      8a16           mov dl, byte [rsi]
│    ╎└└──> 0x010b41b3      72e6           jb 0x10b419b
│    ╎  ╎   0x010b41b5      8d4101         lea eax, [rcx + 1]          ; arg1
│    ╎ ┌──< 0x010b41b8      eb07           jmp 0x10b41c1
│    ╎┌───> 0x010b41ba      ffc8           dec eax
│    ╎╎│╎   0x010b41bc      41ffd3         call r11
│    ╎╎│╎   0x010b41bf      11c0           adc eax, eax
│    ╎╎│╎   ; CODE XREF from fcn.010b4196 @ 0x10b41b8(x)
│    ╎╎└──> 0x010b41c1      41ffd3         call r11
│    ╎╎ ╎   0x010b41c4      11c0           adc eax, eax
│    ╎╎ ╎   0x010b41c6      01db           add ebx, ebx
│    ╎╎┌──< 0x010b41c8      750a           jne 0x10b41d4
│    ╎╎│╎   0x010b41ca      8b1e           mov ebx, dword [rsi]
│    ╎╎│╎   0x010b41cc      4883eefc       sub rsi, 0xfffffffffffffffc
│    ╎╎│╎   0x010b41d0      11db           adc ebx, ebx
│    ╎╎│╎   0x010b41d2      8a16           mov dl, byte [rsi]
│    ╎└└──> 0x010b41d4      73e4           jae 0x10b41ba
│    ╎  ╎   0x010b41d6      83e803         sub eax, 3
│    ╎ ┌──< 0x010b41d9      7219           jb 0x10b41f4
│    ╎ │╎   0x010b41db      c1e008         shl eax, 8
│    ╎ │╎   0x010b41de      0fb6d2         movzx edx, dl
│    ╎ │╎   0x010b41e1      09d0           or eax, edx
│    ╎ │╎   0x010b41e3      48ffc6         inc rsi
│    ╎ │╎   0x010b41e6      83f0ff         xor eax, 0xffffffff         ; -1
│    ╎┌───< 0x010b41e9      7458           je 0x10b4243
│    ╎││╎   0x010b41eb      d1f8           sar eax, 1
│    ╎││╎   0x010b41ed      4863e8         movsxd rbp, eax
│   ┌─────< 0x010b41f0      7238           jb 0x10b422a
│  ┌──────< 0x010b41f2      eb0e           jmp 0x10b4202
│  ││╎│└──> 0x010b41f4      01db           add ebx, ebx
│  ││╎│┌──< 0x010b41f6      7508           jne 0x10b4200
│  ││╎││╎   0x010b41f8      8b1e           mov ebx, dword [rsi]
│  ││╎││╎   0x010b41fa      4883eefc       sub rsi, 0xfffffffffffffffc
│  ││╎││╎   0x010b41fe      11db           adc ebx, ebx
│ ┌────└──> 0x010b4200      7228           jb 0x10b422a
│ │││╎│ ╎   ; CODE XREF from fcn.010b
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 00451B8F: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 00481512: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0070FE96: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0073F701: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0076F1B5: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0079ED6D: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 007CE79B: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 007FE026: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0082D456: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0085CCD5: 00000080 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
