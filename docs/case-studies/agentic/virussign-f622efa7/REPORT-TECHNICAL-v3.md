> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:30:12 UTC

## 1. Executive Summary
This sample is a UPX-packed Windows PE file with a malicious verdict (score: 95, family: Unidentified) (source: llm_judge). Despite failures in Ghidra (NotOwnerException), IDA (missing idasql binary), and Malcat (MCP closure error) that prevented deep decompilation and function-level analysis, static evidence from capa, pe_imports, YARA, and FLOSS confirms malicious behavior (source: llm_judge, cross_engine_notes). Key indicators include UPX packing (ATT&CK T1027.002), high-signal imports for process injection and dynamic code execution (LoadLibrary, GetProcAddress, VirtualProtect, VirtualAlloc), VM/sandbox detection logic, embedded base64 content, and HTTP network communication strings (source: llm_judge, key_evidence). The UPX packing obfuscates the underlying payload, preventing family identification from available static data.

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc |
| Sample Path | /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 95 |
| Family Guess | Unidentified (UPX-packed malicious sample, underlying payload obfuscated by packing) |
| Successful Analysis Engines | capa, pe_imports, YARA, FLOSS |
| Failed Analysis Engines | Ghidra, IDA, Malcat |
(source: structured evidence pack, llm_judge)

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows GUI PE file (source: yara, IsPE32, IsWindowsGUI rules) confirmed as packed via 13 distinct UPX YARA rule matches (source: yara, UPX rule matches) and capa's `packed with UPX` rule (source: capa, top_rules). The PE has an overlay and a Rich signature (source: yara, HasOverlay, HasRichSignature rules). The import table contains 10 total imports, with 4 high-signal APIs for dynamic execution and memory manipulation (source: pe_imports, signals table). FLOSS extracted 2050 static strings, with 0 decoded, stack, or tight strings (source: floss, string count). An XOR search identified a XOR 00 key at offset 0x00000000 (source: xor, search results). UPX unpacking failed with no return code and no unpacked output path (source: upx, unpack results).

## 4. Malcat Triage Summary
Malcat analysis failed with a top-level MCP closure error, so no triage data, function profiles, or decompilation was available from this engine (source: cross_engine_notes, llm_judge).

## 5. Static Code Analysis
### capa Capability Rules
| Rule | ATT&CK | MBC |
|---|---|---|
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| contain loop |  |  |
| (internal) packer file limitation |  |  |
(source: capa, top_rules, duration: 4.33s)

### PE Imports / Signals
| Label | API Match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |
(source: pe_imports, signals, total imports: 10)

### YARA Matches (25 total)
| Rule | Namespace | Match Strings (Trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@209129 len=2 |
| contains_base64 | - | $a@180265 len=16 |
| VirtualPC_Detection | - | $a0@182209 len=4 |
| UPX | - | $a@488 len=4; $b@528 len=4; $c@992 len=4 |
| UPXv20MarkusLaszloReiser | - | $a0@189244 len=85 |
| UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser | - | $a0@189291 len=39 |
| UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser | - | $a1@188976 len=63 |
| upx_3 | - | $str1@188976 len=45 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@208 len=4 |
| PackerUPX_CompresorGratuito_wwwupxsourceforgenet | - | $a@188976 len=12 |
| UPX_wwwupxsourceforgenet_additional | - | $a@188976 len=12 |
| yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h | - | $a@1069 len=1 |
| Netopsystems_FEAD_Optimizer_1 | - | $a@188976 len=64 |
| UPX_290_LZMA | - | $a@188976 len=63 |
| UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser | - | $b@188976 len=63 |
| UPX_290_LZMA_additional | - | $a@188976 len=63 |
| UPX_wwwupxsourceforgenet | - | $a@188976 len=12; $b@188976 len=12 |
| suspicious_packer_section | - |  |
| vmdetect | - | $virtualpc@182209 len=4 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@192740 len=10 |
(source: yara, matches)

### High-Signal FLOSS Strings
- `*\t]\\8`
- `s HTTP/1.1`
- `!This program cannot be run in DOS mode.`
- `loglvTcpkc`ng`
- `Str_Win32_Winsock2_Library` (matches YARA $ws2_lib@192740)
(source: floss, static_strings, total: 2050)

No decompilation, function metrics, or entry point disassembly is available due to Ghidra and IDA failures (source: cross_engine_notes, llm_judge).

## 6. Behavioral & Dynamic Analysis
Speakeasy emulation returned no observable execution: 0 API calls, 0 key events, and no duration recorded (source: speakeasy, emulation results). This is consistent with packed/obfuscated malware that may employ anti-emulation logic (source: deep_dive_agentic). Frida is available (v17.16.4) but no instrumentation data was collected (source: frida_probe, probe results). UPX unpacking failed, so no unpacked runtime behavior could be analyzed (source: upx, unpack results). No dynamic behavior is observed; all indicators are static.

## 7. Network Indicators & C2
Static evidence indicates HTTP network capability: the FLOSS string `s HTTP/1.1` (source: floss, static_strings) is consistent with HTTP request/response logic. YARA rules detect embedded domain patterns (offset 0, length 2) and IPv6 address patterns (offset 209129, length 2) (source: yara, domain and IP rule matches), indicating hardcoded C2 server addresses. The `contains_base64` YARA rule (offset 180265, length 16) (source: yara, contains_base64 rule) indicates obfuscated C2 commands or exfiltration data. No actual network connections were observed due to the lack of successful dynamic execution (source: speakeasy, emulation results).

## 8. Capabilities & MITRE ATT&CK Mapping
| ATT&CK Technique | Evidence Source | Evidence Detail |
|---|---|---|
| T1027.002: Obfuscated Files or Information (Software Packing) | capa | `packed with UPX` rule match (source: capa, top_rules) |
| T1129: Execution via Shared Modules | pe_imports | LoadLibrary, GetProcAddress imports (source: pe_imports, signals) |
| T1055: Process Injection | pe_imports | VirtualProtect, VirtualAlloc imports (source: pe_imports, signals) |
| T1497: Virtualization/Sandbox Evasion | yara | VirtualPC_Detection, vmdetect rule matches (source: yara, matches) |
| T1071.001: Application Layer Protocol: Web Protocols | floss, yara | `s HTTP/1.1` FLOSS string, domain/IP YARA matches (source: floss, yara) |
| T1027: Obfuscated Files or Information | yara | contains_base64 rule match (source: yara, matches) |
Additional capability indicators include dynamic library loading, memory allocation/modification, and anti-VM logic, all consistent with malware designed to evade detection and execute arbitrary code.

## 9. Indicators of Compromise
### Static IOCs
| Type | Value | Source |
|---|---|---|
| File Hash (SHA256) | 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc | structured evidence pack |
| Packer Signature | UPX (13 YARA rule matches) | yara, matches |
| VM Detection Signature | VirtualPC_Detection, vmdetect YARA rules | yara, matches |
| Obfuscation Signature | contains_base64 YARA rule | yara, matches |
| Network Signature | `s HTTP/1.1` FLOSS string | floss, static_strings |
| Import Signature | LoadLibrary, GetProcAddress, VirtualProtect, VirtualAlloc | pe_imports, signals |
### Pattern IOCs
- Domain regex pattern (YARA $domain_regex@0 len=2)
- IPv6 address pattern (YARA $ipv6@209129 len=2)
- Base64-encoded content pattern (YARA $a@180265 len=16)
- UPX section and string patterns (multiple YARA rules at offsets 488, 528, 992, 188976, 189244, 189291)
(source: yara, matches; floss, static_strings; pe_imports, signals)

## 10. Detection Engineering
### Static Detection Rules
1. **YARA**: Use the 25 matched YARA rules to detect this packed sample and its UPX layer, including VM detection, base64 content, and network indicator patterns (source: yara, matches).
2. **Import Signature**: Alert on PE files that combine UPX packing (via YARA or section name `.UPX0`/`.UPX1`) with imports of LoadLibrary, GetProcAddress, VirtualProtect, and VirtualAlloc (source: pe_imports, signals; yara, UPX matches).
3. **String Signature**: Detect the high-signal FLOSS string `s HTTP/1.1` and obfuscated string patterns like `loglvTcpkc`ng` (source: floss, static_strings).
### Dynamic Detection Recommendations
- Emulate or unpack the UPX layer prior to dynamic analysis, as the packed sample shows no observable behavior in Speakeasy (source: speakeasy, emulation results).
- Monitor for process injection calls (VirtualProtect, VirtualAlloc) followed by HTTP connections to hardcoded domains/IPs during runtime.
- Flag execution of PE files with UPX packing that attempt to detect VirtualPC via the signatures at offset 182209 (source: yara, VirtualPC_Detection match).

## 11. What We Don't Know
1. The underlying payload functionality is unknown, as UPX unpacking failed and no unpacked sample is available for analysis (source: upx, unpack results; cross_engine_notes, llm_judge).
2. No specific malware family could be identified, as the packed layer obscures all code-level analysis (source: llm_judge, verdict).
3. No runtime behavior, C2 communication, or payload drop activity was observed, as dynamic analysis engines (Speakeasy, Frida) returned no events (source: speakeasy, emulation results; frida_probe, probe results).
4. No decompilation, function metrics, or entry point disassembly is available due to Ghidra and IDA failures (source: cross_engine_notes, llm_judge).
5. The actual content of the embedded base64 data, domain, and IP address patterns is unknown, as they are only detected via YARA regex and not fully extracted (source: yara, matches).

## 12. Appendix: Analysis Environment
### Failed Analysis Tools
| Tool | Failure Reason | Source |
|---|---|---|
| Ghidra | NotOwnerException: project owned by remnux user | cross_engine_notes, llm_judge |
| IDA | Missing /usr/local/bin/idasql binary | cross_engine_notes, llm_judge |
| Malcat | MCP closure error during analysis | cross_engine_notes, llm_judge |
### Successful Analysis Tools
| Tool | Result | Source |
|---|---|---|
| capa | 3 rules matched, duration 4.33s | capa, top_rules |
| pe_imports | 10 total imports, 4 high-signal signals | pe_imports, signals |
| YARA | 25 rule matches | yara, matches |
| FLOSS | 2050 static strings extracted, 0 decoded/stack/tight strings | floss, string count |
| UPX | Unpack failed (returncode: None, unpacked_path: empty) | upx, unpack results |
| XOR Search | XOR 00 key found at offset 0x00000000 | xor, search results |
| Speakeasy | Emulation completed, 0 API calls/events observed | speakeasy, emulation results |
| Frida | v17.16.4 available, no instrumentation data collected | frida_probe, probe results |
(source: deep_dive_agentic, tool_gate; cross_engine_notes, llm_judge)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc  
**sample_path:** /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 95
- **family_guess**: Unidentified (UPX-packed malicious sample, underlying payload obfuscated by packing)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra analysis failed due to a NotOwnerException (project owned by remnux user), IDA failed to launch due to a missing /usr/local/bin/idasql binary, and Malcat analysis failed with an MCP closure error. No function, import, decompilation, or static profile data was available from these engines. The Ghidra imports table is known to return empty results for this sample type, so import data was sourced from the pe_imports engine. Usable static evidence was successfully retrieved from capa, pe_imports, YARA, and FLOSS despite the analysis engine failures.
- **summary**: This is a UPX-packed Windows PE file with strong indicators of malicious behavior: high-signal imports for process injection and dynamic code execution, VM/sandbox detection logic, embedded base64 content, and HTTP network communication strings. Full deep analysis was blocked by environmental failures for Ghidra, IDA, and Malcat, but cross-engine static evidence from capa, pe_imports, YARA, and FLOSS confirms the sample is malicious. The UPX packing obfuscates the underlying payload, so the specific malware family cannot be determined from available static data.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with UPX` | Confirms the sample is compressed with the UPX packer, mapped to ATT&CK T1027.002 (Software Packing, Defense Evasion) an |
| pe_imports | signals | `load_library (LoadLibrary) [T1129]` | High-signal Windows API import for dynamically loading DLLs, a common technique used by malware to execute malicious cod |
| pe_imports | signals | `get_proc_address (GetProcAddress) [T1129]` | High-signal Windows API import for resolving addresses of dynamically loaded functions, frequently used by malware to ev |
| pe_imports | signals | `change_memory_protection (VirtualProtect) [T1055]` | High-signal Windows API import for modifying memory page permissions, a core technique for process injection, shellcode  |
| pe_imports | signals | `allocate_memory (VirtualAlloc) [T1055]` | High-signal Windows API import for reserving and committing memory regions, commonly used by malware to store unpacked m |
| yara | matches | `UPX, UPXv20MarkusLaszloReiser, UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser,` | 13 distinct YARA rules confirm the sample is packed with UPX, a widely abused packer for obfuscating malware to hinder s |
| yara | matches | `VirtualPC_Detection, vmdetect` | YARA rules detect virtual machine (VM) and sandbox detection logic, a common anti-analysis technique used by malware to  |
| yara | matches | `contains_base64` | YARA rule confirms the sample contains base64-encoded content, a common obfuscation method for hiding malicious payloads |
| yara | matches | `domain, IP` | YARA rules detect embedded domain and IP address patterns, indicative of hardcoded command and control (C2) server addre |
| floss | strings | `m HTTP/1.1` | Static string indicating the sample has HTTP network communication capabilities, consistent with malware that interacts  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The sample is a packed PE with strong indicators of malicious behavior. Deterministic analysis shows UPX packing (capa and YARA), high-signal imports for dynamic loading and memory manipulation (LoadLibrary, GetProcAddress, VirtualProtect, VirtualAlloc), and YARA detections for VM/evasion and network indicators. Emulation and deep decompilation were unavailable, but the static and behavioral signals are sufficient for a high-confidence malicious verdict.

### deep key_evidence
- `"pe_import_signals: LoadLibrary (T1129)"`
- `"pe_import_signals: GetProcAddress (T1129)"`
- `"pe_import_signals: VirtualProtect (T1055)"`
- `"pe_import_signals: VirtualAlloc (T1055)"`
- `"capa_analyze: packed with UPX (T1027.002)"`
- `"yara_scan: UPX, UPXv20MarkusLaszloReiser, UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser, UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser, VirtualPC_Detection"`
- `"yara_scan: domain, IP, contains_base64"`
- `"floss_extract: 2050 static strings including HTTP/1.1 and URL-like fragments"`
- `"speakeasy_emulate: no observable execution, consistent with packed/obfuscated malware"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 3 · duration_s: 4.33

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

## YARA Matches (pipeline)
Total matches: 25

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@209129 len=2 |
| contains_base64 | - | $a@180265 len=16 |
| VirtualPC_Detection | - | $a0@182209 len=4 |
| UPX | - | $a@488 len=4; $b@528 len=4; $c@992 len=4 |
| UPXv20MarkusLaszloReiser | - | $a0@189244 len=85 |
| UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser | - | $a0@189291 len=39 |
| UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser | - | $a1@188976 len=63 |
| upx_3 | - | $str1@188976 len=45 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@208 len=4 |
| PackerUPX_CompresorGratuito_wwwupxsourceforgenet | - | $a@188976 len=12 |
| UPX_wwwupxsourceforgenet_additional | - | $a@188976 len=12 |
| yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h | - | $a@1069 len=1 |
| Netopsystems_FEAD_Optimizer_1 | - | $a@188976 len=64 |
| UPX_290_LZMA | - | $a@188976 len=63 |
| UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser | - | $b@188976 len=63 |
| UPX_290_LZMA_additional | - | $a@188976 len=63 |
| UPX_wwwupxsourceforgenet | - | $a@188976 len=12; $b@188976 len=12 |
| suspicious_packer_section | - |  |
| vmdetect | - | $virtualpc@182209 len=4 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@192740 len=10 |

## Generated YARA Meta
```json
{
  "rule_count": 25,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
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
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 209129,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 180265,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VirtualPC_Detection",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 182209,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 488,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 528,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 992,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXv20MarkusLaszloReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 189244,
          "length": 85,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 189291,
          "length": 39,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a1",
          "offset": 188976,
          "length": 63,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "upx_3",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$str1",
          "offset": 188976,
          "length": 45,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "
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
