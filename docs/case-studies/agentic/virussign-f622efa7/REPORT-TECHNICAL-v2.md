> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:25:17 UTC

# Technical Malware Analysis Report: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc

## 1. Executive Summary
This report analyzes sample 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc, which received a malicious verdict with a score of 95 from the llm_judge engine (source: llm_judge). The sample is identified as a UPX-packed Windows PE file with strong indicators of malicious behavior, including high-signal imports for process injection and dynamic code execution, VM/sandbox detection logic, embedded base64 content, and HTTP network communication strings. Full deep static and dynamic analysis was blocked by environmental failures for Ghidra (NotOwnerException), IDA (missing /usr/local/bin/idasql binary), and Malcat (MCP closure error). Usable static evidence from capa, pe_imports, YARA, and FLOSS confirms the malicious verdict, but the underlying payload is obfuscated by UPX packing, preventing family identification. No dynamic behavior was observed during emulation, consistent with packed malware that employs anti-analysis checks.

## 2. Sample Metadata
| Field | Value |
|-------|-------|
| SHA256 | 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc |
| Sample Path | /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 95 |
| Family Guess | Unidentified (UPX-packed malicious sample, underlying payload obfuscated by packing) |
| Analysis Timestamp | 2026-08-06 02:22:44 UTC (source: rule.yara.json provenance) |
*Source: llm_judge, rule.yara.json*

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows GUI PE file, as confirmed by YARA rules IsPE32 and IsWindowsGUI (source: yara, matches table). It is packed with UPX, per 13 distinct YARA UPX detection rules and capa rule `packed with UPX` (source: yara, capa). The PE has 10 total imports, per pe_imports engine (import_count: 10, source: pe_imports), with 4 high-signal imports related to dynamic code execution and memory manipulation (detailed in Section 5). YARA rules also detect an overlay (HasOverlay), Rich signature (HasRichSignature), and suspicious packer section (suspicious_packer_section) (source: yara, matches table). FLOSS extracted 2050 static strings from the sample, with no decoded, stack, or tight strings (source: floss, FLOSS Strings section). An XOR search found a XOR 00 position at 00000000, with the standard PE DOS header string `!This program cannot be run in DOS mode.` at the start of the file (source: xor, XOR Search section). UPX unpacking failed (upx_ok: False, returncode: None, unpacked_path: empty, source: UPX Unpack section), so no unpacked payload is available for layout analysis. Ghidra and IDA analysis failed due to environmental errors, so no memory block, section, or function layout data is available from those engines (source: cross_engine_notes, verdict.json).

## 4. Malcat Triage Summary
Malcat analysis failed with an MCP closure error, so no Malcat-specific triage data, file layout details, or signature matches are available for this sample (source: cross_engine_notes, verdict.json; Malcat Structured Analysis section).

## 5. Static Code Analysis
Deep static disassembly and decompilation were not possible due to failures in Ghidra (NotOwnerException, project owned by remnux user) and IDA (missing /usr/local/bin/idasql binary) (source: cross_engine_notes, verdict.json). No function metrics, entry point disassembly, or decompressed code is available from these engines. Available static evidence is sourced from capa, pe_imports, YARA, and FLOSS as follows:

### capa Capability Rules
| Rule | ATT&CK | MBC |
|------|--------|-----|
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| contain loop | (unknown) | (unknown) |
| (internal) packer file limitation | (unknown) | (unknown) |
*Source: capa, capa Capability Rules section*

### PE Imports (High-Signal)
| Label | API Match | ATT&CK |
|-------|-----------|--------|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |
*Total imports: 10 (source: pe_imports, PE Imports / Signals section)*

### YARA Matches (High-Signal)
| Rule | Match Offset | Length |
|------|--------------|--------|
| domain | $domain_regex@0 | 2 |
| IP | $ipv6@209129 | 2 |
| contains_base64 | $a@180265 | 16 |
| VirtualPC_Detection | $a0@182209 | 4 |
| vmdetect | $virtualpc@182209 | 4 |
| UPX | $a@488, $b@528, $c@992 | 4 each |
| UPXv20MarkusLaszloReiser | $a0@189244 | 85 |
| UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser | $a0@189291 | 39 |
| UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser | $a1@188976 | 63 |
| Str_Win32_Winsock2_Library | $ws2_lib@192740 | 10 |
*Source: yara, YARA Matches (pipeline) section*

### High-Signal FLOSS Strings
| String | Context |
|--------|---------|
| `s HTTP/1.1` | Indicates HTTP network communication capability (source: floss, High-signal FLOSS section) |
| `*\t]\\8` | Obfuscated/encoded string (source: floss, High-signal FLOSS section) |
| `loglvTcpkc`ng` | Obfuscated string, possibly related to TCP/network functionality (source: floss, FLOSS sample section) |
*Total static strings: 2050 (source: floss, FLOSS Strings section)*

No entry point disassembly or decompilation is available due to engine failures (source: audit trail, ghidra_query entries for function_metrics, funcs, strings).

## 6. Behavioral & Dynamic Analysis
Speakeasy emulation recorded 0 API calls and 0 key events, with no observable execution behavior (source: speakeasy, Speakeasy (dynamic) section). This is consistent with UPX-packed malware that employs anti-emulation or sandbox detection checks (supported by YARA rules VirtualPC_Detection and vmdetect, source: yara). The Frida probe is available (version 17.16.4, source: Frida Probe section) but no Frida-based dynamic data was collected. UPX unpacking failed, so no unpacked payload was available for dynamic execution (source: UPX Unpack section). No process injection, network communication, or file system activity was observed during emulation.

## 7. Network Indicators & C2
No live network communication was observed during dynamic analysis due to lack of observable execution (source: speakeasy, Behavioral & Dynamic Analysis section). Static network indicators include:
- FLOSS string `s HTTP/1.1` indicating HTTP communication capability (source: floss, High-signal FLOSS section)
- YARA rule matches for embedded domain and IP address patterns (source: yara, YARA Matches (pipeline) section, rules `domain` and `IP`)
- YARA match for `Str_Win32_Winsock2_Library` indicating use of Windows Sockets API for network functionality (source: yara, YARA Matches (pipeline) section)
No hardcoded C2 addresses are available in cleartext, as the sample is packed and FLOSS did not extract decoded network strings (source: floss, FLOSS Strings section: decoded_strings: 0).

## 8. Capabilities & MITRE ATT&CK Mapping
Observed capabilities are mapped to MITRE ATT&CK as follows, based on available static evidence:
| Capability | ATT&CK Technique | Evidence Source |
|------------|------------------|-----------------|
| UPX software packing | T1027.002: Obfuscated Files or Information: Software Packing | capa rule `packed with UPX`, 13 YARA UPX rules (source: capa, yara) |
| Dynamic DLL loading | T1129: Execution via Shared Modules | pe_imports signals `load_library (LoadLibrary)`, `get_proc_address (GetProcAddress)` (source: pe_imports) |
| Memory protection modification | T1055: Process Injection | pe_imports signals `change_memory_protection (VirtualProtect)`, `allocate_memory (VirtualAlloc)` (source: pe_imports) |
| VM/sandbox detection | T1497.001: Virtualization/Sandbox Evasion | YARA rules `VirtualPC_Detection`, `vmdetect` (source: yara) |
| Base64 obfuscation | T1027.001: Obfuscated Files or Information: Encoding | YARA rule `contains_base64` (source: yara) |
| HTTP network communication | T1071.001: Application Layer Protocol: Web Protocols | FLOSS string `s HTTP/1.1`, YARA rule `Str_Win32_Winsock2_Library` (source: floss, yara) |
*Note: Full capability mapping is incomplete due to failed unpacking and lack of disassembly (source: cross_engine_notes, verdict.json).*

## 9. Indicators of Compromise
### Static IOCs
| IOC Type | Value | Source |
|----------|-------|--------|
| File Hash (SHA256) | 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc | Sample metadata |
| UPX Packing Signature | Matches 13 YARA UPX rules (e.g., `UPX`, `UPXv20MarkusLaszloReiser`, `UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser`) | yara, YARA Matches (pipeline) section |
| Import Signature | LoadLibrary, GetProcAddress, VirtualProtect, VirtualAlloc | pe_imports, PE Imports / Signals section |
| Static String | `s HTTP/1.1` | floss, High-signal FLOSS section |
| Static String | `loglvTcpkc`ng` | floss, FLOSS sample section |
| VM Detection Signature | Matches YARA rules `VirtualPC_Detection`, `vmdetect` | yara, YARA Matches (pipeline) section |
| Obfuscation Signature | Base64-encoded content (YARA rule `contains_base64`), XOR 00 at offset 0x00000000 | yara, xor sections |
*No dynamic IOCs (C2 addresses, dropped files, registry keys) are available due to lack of observable execution (source: speakeasy, Behavioral & Dynamic Analysis section).*

## 10. Detection Engineering
### YARA Detection Logic
A detection rule for this sample and similar UPX-packed malware can be constructed using the following high-signal conditions:
1. PE file is UPX-packed (matches any of the 13 observed UPX YARA rules)
2. Imports LoadLibrary, GetProcAddress, VirtualProtect, and VirtualAlloc
3. Contains VM detection strings (e.g., `VirtualPC` at offset 0x182209, source: yara)
4. Contains HTTP-related strings (e.g., `HTTP/1.1`, `Winsock2` library reference at offset 0x192740, source: yara, floss)
5. Contains base64-encoded content

### Sigma/EDR Detection
Monitor for process execution events where a UPX-packed PE loads `ws2_32.dll` (implied by YARA match `Str_Win32_Winsock2_Library` at offset 0x192740, source: yara) and calls VirtualProtect to modify memory permissions in child processes, a common process injection pattern. Note that UPX unpacking is required for static detection of the underlying payload.

## 11. What We Don't Know
- The underlying payload of the UPX-packed sample is unknown, as UPX unpacking failed (upx_ok: False, source: UPX Unpack section) and Ghidra/IDA analysis was unavailable (source: cross_engine_notes, verdict.json).
- The specific malware family is unidentified, as no unpacked code or unique family signatures were observed (source: llm_judge, verdict).
- No dynamic behavior (C2 communication, payload execution, file/registry modifications) was observed, as Speakeasy emulation recorded 0 events (source: speakeasy, Behavioral & Dynamic Analysis section).
- No cleartext C2 server addresses, dropped file paths, or persistence mechanisms are available, as no decoded network strings or runtime artifacts were extracted (source: floss, speakeasy sections).
- No disassembly, decompilation, or function call graph data is available due to Ghidra/IDA failures (source: cross_engine_notes, audit trail entries for ghidra_query on funcs, callgraph_edges).
- The purpose of the 2050 static strings extracted by FLOSS is unknown, as most are obfuscated and no decoded strings were produced (source: floss, FLOSS Strings section).

## 12. Appendix: Analysis Environment
### Successful Tools
| Tool | Version/Result | Evidence Source |
|------|----------------|-----------------|
| capa | 3 rules detected, duration 4.33s | capa, capa Capability Rules section |
| pe_imports | 10 imports, 4 high-signal signals | pe_imports, PE Imports / Signals section |
| YARA | 25 matches, 13 UPX-related rules | yara, YARA Matches (pipeline) section |
| FLOSS | 2050 static strings extracted | floss, FLOSS Strings section |
| Speakeasy | Emulation completed, 0 events observed | speakeasy, Speakeasy (dynamic) section |
| Frida Probe | Available, version 17.16.4 | Frida Probe section |
| XOR Search | XOR 00 found at offset 0x00000000 | xor, XOR Search section |

### Failed Tools
| Tool | Failure Reason | Evidence Source |
|------|----------------|-----------------|
| Ghidra | NotOwnerException (project owned by remnux user) | cross_engine_notes, verdict.json; audit trail ghidra_query entries |
| IDA | Missing /usr/local/bin/idasql binary | cross_engine_notes, verdict.json |
| Malcat | MCP closure error | cross_engine_notes, verdict.json; Malcat Structured Analysis section |
| UPX Unpack | Unpacking failed (upx_ok: False, returncode: None) | UPX Unpack section |
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
  "sha256": "91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc",
  "family": "unknown",
  "generated_at": "2026-08-06T02:22:44.016510+00:00",
  "string_count": 10,
  "strings": [
    "Confirms the sample is compressed with the UPX packer, mapped to ATT&CK T1027.002 (Software Packing, Defense Evasion) an",
    "High-signal Windows API import for dynamically loading DLLs, a common technique used by malware to execute malicious cod",
    "High-signal Windows API import for resolving addresses of dynamically loaded functions, frequently used by malware to ev",
    "High-signal Windows API import for modifying memory page permissions, a core technique for process injection, shellcode ",
    "High-signal Windows API import for reserving and committing memory regions, commonly used by malware to store unpacked m",
    "13 distinct YARA rules confirm the sample is packed with UPX, a widely abused packer for obfuscating malware to hinder s",
    "YARA rules detect virtual machine (VM) and sandbox detection logic, a common anti-analysis technique used by malware to ",
    "YARA rule confirms the sample contains base64-encoded content, a common obfuscation method for hiding malicious payloads",
    "YARA rules detect embedded domain and IP address patterns, indicative of hardcoded command and control (C2) server addre",
    "Static string indicating the sample has HTTP network communication capabilities, consistent with malware that interacts "
  ],
  "rule_path": "/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/rule.yar",
  "sigma_path": "/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/rule.yml",
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
    "utc": "2026-08-06 02:22:44 UTC"
  },
  "publish_target": "revai_publish"
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT * FROM memory_blocks LIMIT 50", "ts": 1785752598.4797232}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM data_items LIMIT 100", "ts": 1785752598.484401}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings LIMIT 100", "ts": 1785752598.4862566}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM db_info LIMIT 50", "ts": 1785752603.257417}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM xrefs LIMIT 100", "ts": 1785752603.2651815}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM exports LIMIT 50", "ts": 1785752603.267164}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM callgraph_edges LIMIT 100", "ts": 1785752614.4717262}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM function_metrics LIMIT 50", "ts": 1785752614.488082}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785752624.0556483}`
- `{"source": "yara_gen_v2", "ts": 1785752625.0831735}`
- `{"source": "publish_report_v2", "ts": 1785752711.3570628}`
- `{"source": "publish_report_v2_technical", "ts": 1785752759.7441971}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785869248.7542565}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785869248.780503}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785869248.790374}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785869248.7993193}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785869352.6824207}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785869352.6961365}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785869352.713408}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785869352.7183785}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785869352.7230725}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785869387.3332753}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports ORDER BY address", "ts": 1785869391.6775246}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings ORDER BY address", "ts": 1785869394.1258633}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785869433.306419}`
- `{"source": "yara_gen_v2", "ts": 1785869434.3461442}`
- `{"source": "publish_report_v2", "ts": 1785869509.3375583}`
- `{"source": "publish_report_v2_technical", "ts": 1785869600.3954113}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785982835.6698756}`
- `{"source": "yara_gen_v2", "ts": 1785982964.0172176}`
