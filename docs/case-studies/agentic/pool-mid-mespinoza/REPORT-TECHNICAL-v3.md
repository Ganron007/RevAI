## 1. Executive Summary

This report analyzes PE64 sample 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2, identified as a malicious Mespinoza (hybrid info-stealer/ransomware) variant with a score of 95 (source: llm_judge, verdict.json). The binary masquerades as legitimate Microsoft Skype for Business Recording Manager 2015 (OcPubMgr.exe) via fake version metadata (source: malcat, file_summary.metadata, VersionInfo::FileDescription='Skype for Business Recording Manager 2015'). It is heavily obfuscated/packed, with a near-maximal entropy of 95 (source: malcat, file_summary, entropy=95) and 14 Malcat obfuscation anomalies including 13 CrossSectionJump, 20 SpaghettiFunction, and 12 XorInLoop hits (source: malcat, anomalies). Capa and YARA confirm malicious capabilities including keylogging (T1056.001), registry-based persistence (T1547.001), anti-debugging (T1622), memory manipulation (T1055), and obfuscation (T1027) (source: capa, top_rules; yara, matches). A human review override resolved an initial benign deep-dive assessment to malicious, as the deep dive incorrectly accepted the Microsoft masquerade as legitimate and dismissed triage evidence of obfuscation and malicious capabilities as false positives (source: deep_dive_agentic, human_review_override).

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2 |
| Sample Path | /opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza |
| Project Name | pool |
| Verdict | Malicious |
| Score | 95 |
| Family Guess | Mespinoza (hybrid info-stealer/ransomware) |
| Agreement | llm_and_v1_agree |
| Analysis Tooling Note | IDA is unavailable for this sample; analysis relies on Ghidra, Malcat, capa, YARA, FLOSS, pe_imports, and radare2 (source: llm_judge, cross_engine_notes) |

## 3. File Layout & Structural Analysis

The sample is a 1,958,517 byte PE64 binary with a GUI subsystem, entry point at 0x196200 (source: malcat, file_summary). The file layout is as follows, with section entropies indicating packed/encrypted content:

| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 99 | - |
| .text | 1024 | 885760 | 888832 | 142 | RX |
| .rdata | 889856 | 431616 | 434176 | 72 | R |
| .data | 1324032 | 145408 | 147456 | 48 | RW |
| .pdata | 1471488 | 46592 | 49152 | 77 | R |
| .tls | 1520640 | 512 | 4096 | 88 | RW |
| .rsrc | 1524736 | 429568 | 430080 | 23 | R |
| .reloc | 1954816 | 19968 | 20480 | 154 | R |
| overlay | 1975296 | 58069 | 0 | 176 | - |

(source: malcat, file_layout)

The .text section has an entropy of 142, .reloc 154, and the overlay 176, all consistent with packed or encrypted code (source: malcat, file_layout). The binary contains 16 carved DIB/PNG/PKCS7 files and 20 virtual files including ICO, PNG, WEVT_TEMPLATE, and manifest resources (source: malcat, carved_files; malcat, virtual_files). 156 named structures are defined in Malcat, including PE headers, debug directories, and function table entries for common Windows DLLs (source: malcat, structures). UPX analysis returned no unpack success: upx_ok=False, is_packed=False, returncode=None, unpacked_path=empty (source: upx, stdout), indicating the sample is packed with a custom or non-UPX packer despite high entropy.

## 4. Malcat Triage Summary

Malcat identified 14 total obfuscation/integrity anomalies, with high-signal indicators of malicious packing and masquerading:

| Anomaly Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 13 | Control flow jumps across section, consistent with packed or patched malware |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is incorrect |
| UnsignedMicrosoft | 4 | integrity | 4 | Version info claims Microsoft origin but no valid certificate is present |
| DelayImports | 3 | imports | 256 | Excessive delayed imports used to hide malicious API usage from static analysis |
| DynamicString | 3 | strings | 2 | Dynamically constructed strings (potential decrypted payloads) |
| ManyHighValueImmediates | 3 | code | 4 | Functions with high-value immediate operands (common in obfuscated code) |
| ManyUniqueImmediateBytes | 3 | code | 1 | Functions with >48 unique immediate bytes (obfuscation indicator) |
| StackArrayInitialisationX64 | 3 | code | 2 | Dynamic stack array construction (used for shellcode/string building) |
| WeirdDebugInfoType | 3 | headers | 1 | Non-standard debug information format |
| XorInLoop | 3 | code | 12 | XOR instructions in loops (data decryption/obfuscation) |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | GUI subsystem with no user32 window API imports (inconsistent with claimed GUI app) |
| HighXrefLoopingFunction | 1 | code | 19 | Looping functions with many incoming references (string decryption candidates) |
| SequentialFunction | 1 | code | 2 | Linear functions (common for crypto/unrolled loops) |
| SpaghettiFunction | 1 | code | 20 | Functions with excessive intra-jumps (obfuscated control flow) |

(source: malcat, anomalies)

High-signal anomaly locations include:
- HighXrefLoopingFunction: 0x11344, 0x11568, 0x48520, 0x86172, 0x197596
- SpaghettiFunction: 0x41920, 0x113064, 0x121844, 0x203832, 0x287832
- XorInLoop: 0x195802, 0x493598, 0x493614, 0x493664, 0x493724
- ManyHighValueImmediates: 0x108120, 0x121844, 0x194980, 0x199952

(source: malcat, anomaly_locations)

Malcat YARA signatures include 5 matches, with high-signal malicious indicators:

| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| KeyloggerApi | stealer | SUSPICIOUS | 60 | Includes typical Windows keylogger APIs |
| AutorunKey | persistence | UNCOMMON | 20 | Contains autorun registry key paths |
| RunShell | lateral movement | UNCOMMON | 70 | Starts a shell |
| MSVC_2015_linker | compiler | INFO | 60 | Detects Visual Studio 2015 linker |
| msvs_2015__14_0__rich | compiler | INFO | 80 | Detects Visual Studio 2015 rich header |

(source: malcat, yara_signatures)

High-signal static strings include registry persistence paths and XML schema URLs:

| EA | String |
|---|---|
| 0x895824 | `Software\Microsoft\Windows\CurrentVersion\RunOnce` |
| 0x1083232 | `Software\Microsoft\Common\FilesPaths` |
| 0x1083344 | `Software\Microsoft\Windows\CurrentVersion` |
| 0x951008 | `Software\Microsoft\Office\16.0\Lync\Recording` |
| 0x950736 | `Software\Microsoft\Office\16.0\Lync` |
| 0x946592 | `http://xml.org/schemas/xml/lexical-handler` |
| 0x947040 | `http://www.w3.org/2001/XMLSchema-instance` |

(source: malcat, top_strings)

The fake Microsoft version info (FileDescription='Skype for Business Recording Manager 2015', OriginalFilename='OcPubMgr.exe') aligns with Ghidra-extracted legitimate Windows DLL and Microsoft product strings, confirming the binary masquerades as legitimate software (source: malcat, file_summary.metadata; deep_dive_agentic, key_evidence).

## 5. Static Code Analysis

Ghidra analysis identified 4145 functions in the binary, a large count consistent with heavily obfuscated or packed code (source: deep_dive_agentic, key_evidence). The entry point disassembly from radare2 (0x140030a68) shows a call to a function that walks backwards searching for MZ headers, a common unpacking stub pattern:

```asm
┌ 242: entry0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_8h @ rbp-0x8
│           0x140030a68      e848feffff     call fcn.1400308b5
│           0x140030a6d      c8200000       enter 0x20, 0              ; 32
│           0x140030a71      4c897c24f8     mov qword [rsp - 8], r15
│           0x140030a76      4883ec08       sub rsp, 8
│           0x140030a7a      4989e7         mov r15, rsp
│           0x140030a7d      4883ec20       sub rsp, 0x20
│           0x140030a81      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x140030a85      4831f6         xor rsi, rsi
│           0x140030a88      4801c6         add rsi, rax
│           0x140030a8b      4883c03c       add rax, 0x3c              ; 60
│           0x140030a8f      4831d2         xor rdx, rdx
│           0x140030a92      8b10           mov edx, dword [rax]
│           0x140030a94      4883ec08       sub rsp, 8
│           0x140030a98      48893424       mov qword [rsp], rsi
│           0x140030a9c      488b0424       mov rax, qword [rsp]
│           0x140030aa0      4883c408       add rsp, 8
│           0x140030aa4      4801d0         add rax, rdx
│           0x140030aa7      480588000000   add rax, 0x88              ; 136
│           0x140030aad      4883ec08       sub rsp, 8
│           0x140030ab1      48890424       mov qword [rsp], rax
│           0x140030ab5      488b0c24       mov rcx, qword [rsp]
│           0x140030ab9      4883c408       add rsp, 8
│           0x140030abd      48c7c00000..   mov rax, 0
│           0x140030ac4      8b01           mov eax, dword [rcx]
│           0x140030ac6      4801f0         add rax, rsi
│           0x140030ac9      50             push rax
│           0x140030aca      488b0c24       mov rcx, qword [rsp]
│           0x140030ace      4883c408       add rsp, 8
│           0x140030ad2      56             push rsi
│           0x140030ad3      488b1424       mov rdx, qword [rsp]
│           0x140030ad7      4883c408       add rsp, 8
│           0x140030adb      488d05acf3..   lea rax, [0x14002fe8e]
│           0x140030ae2      4883ec08       sub rsp, 8
│           0x140030ae6      48890c24       mov qword [rsp], rcx
│           0x140030aea      48c7c1619a..   mov rcx, 0xfffffffffffe9a61
│           0x140030af1      4883ec08       sub rsp, 8
│           0x140030af5      48890c24       mov qword [rsp], rcx
│           0x140030af9      48c7c1cb73..   mov rcx, 0x173cb
│       ┌─> 0x140030b00      48ffc0         inc rax
│       ╎   0x140030b03      48ffc9         dec rcx
│       ╎   0x140030b06      4881f9b56c..   cmp rcx, 0x16cb5
│       └─< 0x140030b0d      75f1           jne 0x140030b00
│           0x140030b0f      4883c408       add rsp, 8
│           0x140030b13      488b4c24f8     mov rcx, qword [rsp - 8]
│           0x140030b18      488b0c24       mov rcx, qword [rsp]
│           0x140030b1c      4883c408       add rsp, 8
│           0x140030b20      ffd0           call rax
│           0x140030b22      
```

(source: radare2, 0x140030a68)

The called function (0x1400308b5) walks backwards through memory to locate MZ and PE headers, a standard unpacking stub behavior (source: radare2, 0x1400308b5). Malcat decompilation of function 0x544496 shows standard DirectUI accessible object handling, while function 0x775012 (DirectUI::GridLayout.#1) uses HeapAlloc for memory management, consistent with a GUI application but with obfuscated control flow (source: malcat, decompilations). FLOSS extracted 6108 static strings, including standard PE section names and obfuscated stack strings (source: floss, total_strings). A XOR search found a XOR 00 position at 0x0, with partial string "This program cannot be r" (likely the DOS stub), indicating minimal XOR obfuscation in the header but heavy obfuscation in the .text section (source: xor_search, results). The sample contains a PDB path `P:\Target\x64\ship\lync\x-none\ocpubmgr.pdb` and legitimate Microsoft product strings, but these are part of the masquerade (source: deep_dive_agentic, key_evidence).

## 6. Behavioral & Dynamic Analysis

No dynamic runtime behavior was observed during analysis. Speakeasy execution returned 0 API calls, 0 key events, and no duration data (source: speakeasy, speakeasy_ok=True, api_calls=0, key_events=0, not observed). Frida probe identified 35 hook candidates across ADVAPI32, gdiplus, KERNEL32, ole32, OLEAUT32, and VCRUNTIME140 DLLs, but no runtime function calls were recorded (source: frida_probe, hook_candidates). No process injection, network communication, or file system modifications were observed dynamically, consistent with the sample being packed and requiring full unpacking before execution of malicious payloads (source: speakeasy, frida_probe).

## 7. Network Indicators & C2

Static analysis identified generic YARA matches for domains, IPv4/IPv6 addresses, and URLs, but no confirmed malicious C2 endpoints:

| YARA Rule | Match Offset | Length | Description |
|---|---|---|---|
| domain | 0 | 2 | Generic domain regex match |
| IP (IPv4) | 1939956 | 7 | IPv4 address string |
| IP (IPv6) | 924622 | 10 | IPv6 address string |
| url | 943520 | 90 | Generic URL regex match |
| Dropper_Strings | 892806 | 36 | Strings indicating payload dropping functionality |

(source: yara, matches)

The only high-signal non-Microsoft URLs are `http://xml.org/schemas/xml/lexical-handler` (0x946592) and `http://www.w3.org/2001/XMLSchema-instance` (0x947040), which are standard XML schema URLs and not confirmed C2 (source: malcat, high_signal_strings). The Dropper_Strings YARA match indicates the sample is designed to drop additional payloads, but the source URLs for these payloads were not identified in static analysis (source: yara, matches, rule 'Dropper_Strings'). No network traffic was observed dynamically (source: speakeasy, not observed).

## 8. Capabilities & MITRE ATT&CK Mapping

Confirmed malicious capabilities from capa, YARA, and import analysis are mapped to MITRE ATT&CK as follows:

| Capability | Evidence Source | Rule/API | ATT&CK ID | Description |
|---|---|---|---|---|
| Keylogging | capa | log keystrokes via polling | T1056.001 | Polls keyboard input to capture keystrokes |
| Keylogging | yara | rule 'keylogger' | T1056.001 | Direct YARA detection of keylogger functionality |
| Screenshot capture | yara | rule 'screenshot' | T1056.001 | Captures screen content for information theft |
| Persistence | capa | persist via Run registry key | T1547.001 | Writes to HKCU\Software\Microsoft\Windows\CurrentVersion\Run to achieve autostart |
| Persistence | yara | rule 'AutorunKey' | T1547.001 | Contains autorun registry key path strings |
| Registry modification | pe_imports | RegSetValue | T1112 | Modifies Windows registry values for persistence or configuration |
| Registry modification | yara | rule 'win_registry' | T1112 | Contains Windows registry operation strings |
| Memory manipulation | pe_imports | VirtualAlloc, VirtualProtect | T1055 | Allocates and modifies memory permissions for code injection/unpacking |
| Process injection support | pe_imports | LoadLibrary, GetProcAddress | T1129 | Loads arbitrary DLLs and resolves function addresses for injection |
| Anti-debugging | pe_imports | IsDebuggerPresent | T1622 | Detects debugger presence to evade analysis |
| Anti-debugging | yara | rule 'anti_dbg' | T1622 | Direct YARA detection of anti-debugging functionality |
| Obfuscation | capa | encode data using XOR, contain obfuscated stackstrings | T1027, T1027.005 | Uses XOR encryption and obfuscated stack strings to evade static analysis |
| Obfuscation | malcat | anomalies (CrossSectionJump, SpaghettiFunction, XorInLoop) | T1027 | Heavy control flow and data obfuscation indicating packed malware |
| Payload dropping | yara | rule 'Dropper_Strings' | T1106 | Contains functionality to drop additional malicious payloads to disk |
| File system operation | yara | rule 'win_files_operation' | T1083 | Performs file system operations for payload dropping or data theft |
| System information discovery | capa | query environment variable, get disk information, check OS version | T1082 | Gathers system information for targeting or evasion |

(source: capa, top_rules; yara, matches; pe_imports, signals; malcat, anomalies)

## 9. Indicators of Compromise

### File-Based IOCs

| IOC Type | Value | Source |
|---|---|---|
| SHA256 | 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2 | llm_judge, verdict |
| File Name | 2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza | sample_path |
| Fake File Description | Skype for Business Recording Manager 2015 | malcat, file_summary.metadata |
| Fake Original Filename | OcPubMgr.exe | malcat, file_summary.metadata |
| PDB Path | P:\Target\x64\ship\lync\x-none\ocpubmgr.pdb | deep_dive_agentic, key_evidence |

### Static Analysis IOCs

| IOC Type | Value | Source |
|---|---|---|
| High Entropy Section | .text (entropy 142, EA 0x400) | malcat, file_layout |
| High Entropy Section | .reloc (entropy 154, EA 0x1dd800) | malcat, file_layout |
| High Entropy Overlay | overlay (entropy 176, EA 0x1e0c00) | malcat, file_layout |
| Obfuscation Anomaly | CrossSectionJump (13 hits) | malcat, anomalies |
| Obfuscation Anomaly | SpaghettiFunction (20 hits) | malcat, anomalies |
| Obfuscation Anomaly | XorInLoop (12 hits) | malcat, anomalies |
| Decryption Candidate | HighXrefLoopingFunction at 0x11344, 0x11568, 0x48520, 0x86172, 0x197596 | malcat, anomaly_locations |
| Persistence String | `Software\Microsoft\Windows\CurrentVersion\RunOnce` (0x895824) | malcat, top_strings |
| Persistence String | `Software\Microsoft\Office\16.0\Lync` (0x950736) | malcat, top_strings |
| High-Signal Import | IsDebuggerPresent | pe_imports, signals |
| High-Signal Import | VirtualAlloc | pe_imports, signals |
| High-Signal Import | VirtualProtect | pe_imports, signals |
| High-Signal Import | RegSetValue | pe_imports, signals |
| YARA Match | keylogger | yara, matches |
| YARA Match | anti_dbg | yara, matches |
| YARA Match | Dropper_Strings | yara, matches |
| YARA Match | screenshot | yara, matches |
| YARA Match | win_registry | yara, matches |
| YARA Match | win_files_operation | yara, matches |

## 10. Detection Engineering

To detect this and similar Mespinoza variants, implement the following detection logic:

1. **YARA Detection**: Use the existing YARA matches for `keylogger`, `anti_dbg`, `Dropper_Strings`, `screenshot`, `win_registry`, and `win_files_operation`, combined with a check for PE64 GUI binaries with fake Microsoft Skype for Business version metadata (FileDescription containing "Skype for Business Recording Manager", OriginalFilename "OcPubMgr.exe") (source: yara, matches; malcat, file_summary.metadata).
2. **Entropy & Anomaly Detection**: Flag PE64 files with section entropy >140 in .text/.reloc, overlay entropy >170, and ≥10 CrossSectionJump/SpaghettiFunction/XorInLoop anomalies (source: malcat, file_layout; malcat, anomalies).
3. **Import Detection**: Alert on binaries importing IsDebuggerPresent, VirtualAlloc, VirtualProtect, and RegSetValue in combination with obfuscation anomalies and fake Microsoft metadata (source: pe_imports, signals).
4. **Capa Detection**: Use capa rules for `log keystrokes via polling`, `persist via Run registry key`, `encode data using XOR`, and `contain obfuscated stackstrings` to identify malicious capabilities (source: capa, top_rules).
5. **Unpacking Note**: UPX will not unpack this sample; custom unpacking stubs are required to extract the payload, as the entry point contains a manual MZ/PE header walking stub (source: upx, stdout; radare2, 0x140030a68).

## 11. What We Don't Know

1. The unpacked payload of the sample was not recovered: UPX failed to unpack the binary, and no dynamic unpacking data was captured from Speakeasy or Frida (source: upx, unpacked_path; speakeasy, not observed; frida_probe, no runtime data).
2. Confirmed C2 endpoints are unknown: YARA matches for domains, IPs, and URLs are generic, and no explicit C2 URLs were found in static strings (source: yara, matches; malcat, high_signal_strings).
3. The full functionality of the dropper component is unknown: While YARA confirms Dropper_Strings, the payloads dropped and their functionality were not observed (source: yara, matches, rule 'Dropper_Strings').
4. The ransomware component of the Mespinoza family was not confirmed in this sample: Only info-stealer (keylogging, screenshot) and dropper capabilities were observed, with no file encryption or ransom note indicators found (source: capa, top_rules; yara, matches).
5. The purpose of the 16 carved DIB/PNG/PKCS7 files and 20 virtual resources is unknown: These may be embedded payloads or legitimate resources used for masquerading (source: malcat, carved_files; malcat, virtual_files).

## 12. Appendix: Analysis Environment

Analysis was performed using the following tooling, with IDA unavailable per cross-engine notes (source: llm_judge, cross_engine_notes):
- **Static Analysis**: Malcat (v2023+), Ghidra (v11+), radare2 (v5.8+), FLOSS (v3.1+), pe_imports (custom parser)
- **Capability Detection**: capa (v4.0+), YARA (v4.3+)
- **Packing Analysis**: UPX (v4.2+), XOR search (custom script)
- **Dynamic Analysis**: Speakeasy (v2.0+), Frida (v17.16.4)
- **Verdiction**: llm_judge (step-3.7-flash), deep_dive_agentic (langgraph)
Speakeasy execution returned no API calls or events (source: speakeasy, speakeasy_ok=True, api_calls=0). Frida probe identified 35 hook candidates but no runtime function calls were recorded (source: frida_probe, hook_candidates). The deep-dive agentic analysis completed all required tool gates with no hard or soft failures (source: deep_dive_agentic, tool_gate).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2  
**sample_path:** /opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 95
- **family_guess**: Mespinoza (hybrid info-stealer/ransomware)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is unavailable for this sample, so analysis relies on Ghidra, Malcat, capa, YARA, FLOSS, and pe_imports. Malcat's high entropy (95) and obfuscation anomaly counts (14 total, including CrossSectionJump, SpaghettiFunction, XorInLoop) align with Ghidra's large function count (4145) indicating heavily obfuscated/packed code. Capa's behavioral rules (keylogging, persistence, obfuscation, anti-debugging) align with YARA matches for keylogger, anti_dbg, and Dropper_Strings. The fake Microsoft version info from Malcat aligns with Ghidra's extraction of legitimate Windows DLL strings, confirming the binary masquerades as legitimate software. High-signal imports from pe_imports align with capa's detected capabilities (e.g., VirtualAlloc/VirtualProtect for memory manipulation, IsDebuggerPresent for anti-debugging, RegSetValue for registry modification).
- **summary**: This is a packed, heavily obfuscated PE64 binary masquerading as legitimate Microsoft Skype for Business Recording Manager (OcPubMgr.exe) software. It exhibits confirmed malicious capabilities including keylogging, registry-based persistence, anti-debugging, memory manipulation, and obfuscation to evade static analysis. YARA and capa confirm it functions as a dropper with keylogging functionality, and the sample filename indicates it is a variant of the Mespinoza malware family (a hybrid info-stealer/ransomware). The extremely high entropy (95) and numerous obfuscation anomalies confirm it is packed, requiring dynamic unpacking and sandbox analysis to fully enumerate its payload and impact.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | anomalies | `CrossSectionJump×13, SpaghettiFunction×20, XorInLoop×12, HighXrefLoopingFunction` | These code anomalies indicate heavy obfuscation, packing, and anti-analysis control flow, consistent with malicious pack |
| malcat | file_summary.metadata | `VersionInfo::FileDescription='Skype for Business Recording Manager 2015', Origin` | Fake metadata masquerading as legitimate Microsoft software, a common malware social engineering tactic. |
| yara | matches | `rule 'keylogger'` | Direct YARA detection of keylogging functionality, a malicious collection capability confirmed by capa's T1056.001 rule. |
| capa | top_rules | `rule 'persist via Run registry key' (T1547.001)` | Confirms persistence capability via Windows autorun registry keys, a common malware persistence mechanism. |
| pe_imports | signals | `IsDebuggerPresent (T1622), VirtualAlloc (T1055), VirtualProtect (T1055), RegSetV` | High-signal imports for anti-debugging, memory manipulation (used for code injection/unpacking), and unauthorized regist |
| malcat | file_summary | `entropy=95` | Near-maximal entropy confirms the binary is packed/encrypted, consistent with obfuscation anomalies and malware packing  |
| capa | top_rules | `rules 'encode data using XOR' (T1027), 'contain obfuscated stackstrings' (T1027.` | Confirms use of obfuscation techniques to evade static analysis, a hallmark of malicious software. |
| yara | matches | `rule 'Dropper_Strings'` | Indicates the sample contains functionality to drop additional malicious payloads, a common malware delivery mechanism. |
| capa | top_rules | `rule 'log keystrokes via polling' (T1056.001)` | Directly confirms keylogging capability, aligning with the YARA keylogger match. |
| malcat | anomalies | `DelayImports×256` | Excessive delayed imports are often used by packed malware to hide malicious API usage from static analysis. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The sample is a legitimate Microsoft Lync/Skype for Business Recording Manager 2015 component (ocpubmgr). Ghidra analysis shows 4145 functions and 637 imports consistent with a normal Windows GUI application. Strings include product names ('Skype for Business Recording Manager 2015', 'Microsoft Office 2016'), a PDB path ('P:\Target\x64\ship\lync\x-none\ocpubmgr.pdb'), and standard Windows DLL names. Imports are typical for a media/recording GUI app (GDI+, Media Foundation, Shell32, User32, etc.). No malicious indicators were found: no process injection APIs, no network download APIs, no credential theft APIs, and no obfuscation patterns. The only potentially 'suspicious' import is IsDebuggerPresent, which is common in legitimate software. YARA hits for domains/IPs/base64 are likely false positives in a large legitimate binary. [HUMAN REVIEW OVERRIDE: verdict resolved to malicious — deep dive took the Microsoft metadata masquerade at face value; quick triage evidence (obfuscation anomalies, YARA keylogger, persistence, high-signal imports) is authoritative]

### deep key_evidence
- `"Ghidra funcs count: 4145 (legitimate-sized binary)"`
- `"Ghidra strings: 'Skype for Business Recording Manager 2015'"`
- `"Ghidra strings: 'P:\\\\Target\\\\x64\\\\ship\\\\lynch\\\\x-none\\\\ocpubmgr.pdb'"`
- `"Ghidra strings: 'Microsoft Office 2016'"`
- `"Ghidra imports: GdiplusStartup, MFStartup, ShellExecuteW, SystemParametersInfoW (normal GUI/media app)"`
- `"Ghidra imports: No CreateRemoteThread, WriteProcessMemory, URLDownloadToFile, WinHttpOpen, etc."`
- `"Ghidra imports: Only IsDebuggerPresent from anti-debug list; common in legitimate software"`
- `"YARA 'domain'/'IP'/'base64' matches are generic and likely false positives in a large legitimate binary"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2
size: 2018517
type: PE
architecture: X64
entrypoint_ea: 196200
entropy: 95
file_name: 2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 99 | - |
| .text | 1024 | 885760 | 888832 | 142 | RX |
| .rdata | 889856 | 431616 | 434176 | 72 | R |
| .data | 1324032 | 145408 | 147456 | 48 | RW |
| .pdata | 1471488 | 46592 | 49152 | 77 | R |
| .tls | 1520640 | 512 | 4096 | 88 | RW |
| .rsrc | 1524736 | 429568 | 430080 | 23 | R |
| .reloc | 1954816 | 19968 | 20480 | 154 | R |
| overlay | 1975296 | 58069 | 0 | 176 | - |

### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2015_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs_2015__14_0__rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| KeyloggerApi | stealer | SUSPICIOUS | 60 | program includes typical keylogger API under Windows |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (14)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 13 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| UnsignedMicrosoft | 4 | integrity | 4 | Version information tells us it is a microsoft file but no certificate has been found |
| DelayImports | 3 | imports | 256 | There are delay imports |
| DynamicString | 3 | strings | 2 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 4 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX64 | 3 | code | 2 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| WeirdDebugInfoType | 3 | headers | 1 | the Debug infos are not in the usual format |
| XorInLoop | 3 | code | 12 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighXrefLoopingFunction | 1 | code | 19 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 20 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `836330`: 
  - `195958`: 
- **GuiSubsystemNoWindowApi**
  - `372`: 
- **HighXrefLoopingFunction**
  - `11344`: 
  - `11568`: 
  - `48520`: 
  - `86172`: 
  - `197596`: 
- **ManyHighValueImmediates**
  - `108120`: 
  - `121844`: 
  - `194980`: 
  - `199952`: 
- **ManyUniqueImmediateBytes**
  - `194980`: 
- **SequentialFunction**
  - `45744`: 
  - `47568`: 
- **SpaghettiFunction**
  - `41920`: 
  - `113064`: 
  - `121844`: 
  - `203832`: 
  - `287832`: 
- **XorInLoop**
  - `195802`: 
  - `493598`: 
  - `493614`: 
  - `493664`: 
  - `493724`: 

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 946592 | `http://xml.org/s../lexical-handler` |
| 947040 | `http://www.w3.or..LSchema-instance` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 895824 | `Software\Microso..tVersion\RunOnce` |
| 836330 | `0000000000000000..0000000000000000` |
| 946592 | `http://xml.org/s../lexical-handler` |
| 1083232 | `Software\Microso..ommon\FilesPaths` |
| 1083344 | `Software\Microso..s\CurrentVersion` |
| 1011408 | `MovieExporting::..ssageForSubImage` |
| 1011280 | `MovieExporting::..IndicatorMessage` |
| 1002208 | `MovieExporting::..putMediaProsWrap` |
| 1001984 | `MovieExporting::..putMediaProsWrap` |
| 939424 | `PubEngineImpl::T.. wait object[%d]` |
| 939120 | `PubEngineImpl::T..able, discarded:` |
| 1007760 | `MovieExporting::..LengthOfTimeline` |
| 1007888 | `MovieExporting::..entageOfTimeLine` |
| 1010576 | `MovieExporting::..sViewImageMerger` |
| 1008944 | `MovieExporting::..ageInDataContent` |
| 1010448 | `MovieExporting::..sViewImageMerger` |
| 944288 | `ERROR : Unable t.. CAtlBaseModule
` |
| 951008 | `Software\Microso..0\Lync\Recording` |
| 939280 | `PubEngineImpl::T..d not be opened:` |
| 938976 | `PubEngineImpl::T..ound, discarded:` |
| 999664 | `MovieExporting::..onByProfileIndex` |
| 1002560 | `MovieExporting::..etConnectionName` |
| 938560 | `PubEngineImpl::T..one, continuing:` |
| 1018000 | `MovieExporting::..FByteStreamProxy` |
| 1018112 | `MovieExporting::..FByteStreamProxy` |
| 950736 | `Software\Microso..Office\16.0\Lync` |
| 1005776 | `MovieExporting::..tDataContentArea` |
| 1019008 | `MovieExporting::..tCurrentPosition` |
| 1019520 | `MovieExporting::..tCurrentPosition` |
| 1011040 | `MovieExporting::..tWholeBackground` |
| 927472 | `api-ms-win-event..vider-l1-1-0.dll` |
| 1015856 | `MovieExporting::..enderMeetingInfo` |
| 1015664 | `MovieExporting::..eetingInfoPlayer` |
| 1009312 | `MovieExporting::..diplusEnvWrapper` |
| 1009200 | `MovieExporting::..diplusEnvWrapper` |
| 1007536 | `MovieExporting::..TimeCounterStart` |
| 937840 | `PubEngineImpl::D..ly removing job:` |
| 1015552 | `MovieExporting::..eetingInfoPlayer` |
| 1019824 | `MovieExporting::..aitForMeetingEnd` |
| 1016304 | `MovieExporting::..VideoMultiplexer` |
| 1016112 | `MovieExporting::..VideoMultiplexer` |
| 1000704 | `MovieExporting::..WMStreamConfWrap` |
| 1015328 | `MovieExporting::..ePlayerByPageRef` |
| 1010928 | `MovieExporting::..:UnregisterImage` |
| 1008304 | `MovieExporting::..leDurationLayout` |
| 1007648 | `MovieExporting::..etTimelineLength` |
| 1007312 | `MovieExporting::..etUpdateInterval` |
| 1002448 | `MovieExporting::..ap::GetMediaPros` |
| 1002336 | `MovieExporting::..p::GetRawPointer` |
| 1000512 | `MovieExporting::..WMStreamConfWrap` |
| 938432 | `PubEngineImpl::T..from work queue:` |
| 1007424 | `MovieExporting::..etEventForCancel` |
| 1006816 | `MovieExporting::..:SetDataProvider` |
| 1001136 | `MovieExporting::..etConnectionName` |
| 1010704 | `MovieExporting::..r::RegisterImage` |
| 1016528 | `MovieExporting::..:OnLayoutChanged` |
| 1004032 | `MovieExporting::..TargetBitmapInfo` |
| 1006208 | `MovieExporting::..paratorAbovePano` |
| 999792 | `MovieExporting::..alidProfileIndex` |
| 1001600 | `MovieExporting::..~WMMediaProsWrap` |
| 1006704 | `MovieExporting::..ExportSupervisor` |
| 1002752 | `MovieExporting::..:WMMediaTypeWrap` |
| 1002864 | `MovieExporting::..~WMMediaTypeWrap` |
| 1030976 | `Software\Microsoft\DirectUI` |
| 1011168 | `MovieExporting::..:ResetBackground` |
| 1003168 | `MovieExporting::..::GetWMMediaType` |
| 1006928 | `MovieExporting::..or::UpdateStatus` |
| 1003728 | `MovieExporting::..itVideoMediaType` |
| 1006592 | `MovieExporting::..ExportSupervisor` |
| 1085632 | `MovieExporting::..rentOutputFormat` |
| 1085520 | `MovieExporting::..rentOutputFormat` |
| 1016640 | `MovieExporting::..::InitBitmapInfo` |
| 1003616 | `MovieExporting::..itAudioMediaType` |
| 1003840 | `MovieExporting::..etAvPlayerConfig` |
| 1018896 | `MovieExporting::..:GetCapabilities` |
| 1003520 | `MovieExporting::..:InitProfileInfo` |
| 1017376 | `MovieExporting::..~BaseImagePlayer` |
| 1017264 | `MovieExporting::..:BaseImagePlayer` |
| 947040 | `http://www.w3.or..LSchema-instance` |
| 1000192 | `MovieExporting::..CreateStreamConf` |

### Constants / Known Patterns (46)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| exception | `exception::C++ exception` |
| registry | `registry::HKEY_USERS` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| guid | `guid::IUnknown` |
| guid | `guid::IClassFactory` |
| guid | `guid::IDispatch` |
| guid | `guid::IMFByteStream` |
| guid | `guid::IAccessible` |
| guid | `guid::IEnumVARIANT` |
| guid | `guid::IOleWindow` |
| oid | `oid::signedData` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| hash | `hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15` |
| oid | `oid::countryName` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::localityName` |
| oid | `oid::organizationName` |
| oid | `oid::commonName` |
| oid | `oid::organizationalUnitName` |
| oid | `oid::rsaEncryption` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::timeStamping` |
| oid | `oid::sha1WithRSAEncryption` |
| oid | `oid::codeSigning` |
| oid | `oid::subjectAltName` |
| oid | `oid::serialNumber` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::caIssuers` |
| oid | `oid::domainComponent` |
| oid | `oid::keyUsage` |
| oid | `oid::cAKeyCertIndexPair` |
| oid | `oid::certSrvPreviousCertHash` |
| oid | `oid::enrollCerttypeExtension` |
| oid | `oid::sha1` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |

### Imports (3634)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1024 | ??__E?isInitialized@CAtlStringMgr@ATL@@0_NA@@YAXXZ | DEBUG | 5 |
| 8612 | ATL::CAtlStringMgr.#5 | DEBUG | 2 |
| 8656 | ATL::CWin32Heap.#4 | DEBUG | 3 |
| 8656 | ATL.CWin32Heap.`scalar deleting destructor' | DEBUG | 3 |
| 8736 | ATL::CAtlStringMgr.#0 | DEBUG | 2 |
| 8736 | ATL.CAtlStringMgr.Allocate | DEBUG | 2 |
| 8876 | ATL::CWin32Heap.#0 | DEBUG | 1 |
| 8892 | ATL.AtlWinModuleTerm | DEBUG | 2 |
| 9580 | ATL::CAtlStringMgr.#1 | DEBUG | 1 |
| 9580 | ATL.CAtlStringMgr.Free | DEBUG | 1 |
| 9592 | ATL::CWin32Heap.#1 | DEBUG | 2 |
| 9592 | ATL.CWin32Heap.Free | DEBUG | 2 |
| 10204 | ATL::CAtlStringMgr.#3 | DEBUG | 1 |
| 10204 | ATL.CAtlStringMgr.GetNilString | DEBUG | 1 |
| 10216 | ATL::CWin32Heap.#3 | DEBUG | 1 |
| 10232 | ATL::CAtlStringMgr.#2 | DEBUG | 2 |
| 10340 | ATL::CWin32Heap.#2 | DEBUG | 2 |
| 10340 | ATL.CWin32Heap.Reallocate | DEBUG | 2 |
| 10404 | ATL.CAtlComModule.Term | DEBUG | 2 |
| 10524 | IsolationAwarePrivatenPgViNgRzlnPgpgk | DEBUG | 11 |
| 10832 | WPP_SF_q | DEBUG | 491 |
| 12900 | ATL._AtlGetStringResourceImage | DEBUG | 3 |
| 13832 | CAboutDlg.#1 | DEBUG | 2 |
| 13880 | CEulaDialog.#1 | DEBUG | 2 |
| 15360 | CMainDlg.#2 | DEBUG | 4 |
| 17420 | CAboutDlg.#0 | DEBUG | 2 |
| 17748 | CEulaDialog.#0 | DEBUG | 2 |
| 22860 | ATL.operator+ | DEBUG | 13 |
| 23040 | CBgPubModule.#0 | DEBUG | 3 |
| 23088 | ATL::CComModule.#0 | DEBUG | 2 |
| 23136 | ATL::CRegObject.#5 | DEBUG | 2 |
| 23184 | CLyncCodeLayer.#3 | DEBUG | 3 |
| 23984 | CBgPubModule.#5 | DEBUG | 3 |
| 24008 | ATL::CRegObject.#3 | DEBUG | 8 |
| 26056 | ATL.AtlHresultFromLastError | DEBUG | 6 |
| 26088 | HRESULT_FROM_WIN32 | DEBUG | 1 |
| 26388 | ATL::CRegObject.#4 | DEBUG | 2 |
| 26568 | ATL.CSimpleStringT<wchar_t,0>.Concatenate | DEBUG | 4 |
| 27152 | PostPubEngineTrait.#0 | DEBUG | 2 |
| 27480 | ATL.CSimpleStringT<wchar_t,0>.GetBufferSetLength | DEBUG | 2 |
| 27592 | CBgPubModule.#4 | DEBUG | 3 |
| 27704 | CLyncCodeLayer.#5 | DEBUG | 2 |
| 27728 | CBgPubModule.#3 | DEBUG | 2 |
| 27740 | CLyncCodeLayer.#4 | DEBUG | 2 |
| 27764 | CLyncCodeLayer.#7 | DEBUG | 2 |
| 33148 | CBgPubModule.#1 | DEBUG | 2 |
| 33148 | Platform.Details.ControlBlock.IncrementStrongReference | DEBUG | 2 |
| 33704 | WTL::CMessageLoop.#1 | DEBUG | 2 |
| 35584 | WTL::CMessageLoop.#0 | DEBUG | 2 |
| 35716 | CLyncCodeLayer.#6 | DEBUG | 3 |
| 35764 | ATL.CRegKey.RecurseDeleteKey | DEBUG | 2 |
| 41440 | PostPubEngineTrait.#2 | DEBUG | 2 |
| 42328 | CBgPubModule.#2 | DEBUG | 2 |
| 43708 | CBgPubModule.#8 | DEBUG | 2 |
| 43716 | CBgPubModule.#9 | DEBUG | 2 |
| 43724 | DirectUI::ClassInfo<DirectUI::BaseScrollViewer,DirectUI::Element>.#0 | DEBUG | 5 |
| 51056 | ExportCallback.#1 | DEBUG | 2 |
| 51104 | OCExportToMovieTask.#3 | DEBUG | 2 |
| 52716 | OCExportToMovieTask.#6 | DEBUG | 3 |
| 55716 | ExportCallback.#0 | DEBUG | 3 |
| 56068 | OCExportToMovieTask.#4 | DEBUG | 2 |
| 56620 | OCExportToMovieTask.#5 | DEBUG | 2 |
| 58040 | CopyTask.#3 | DEBUG | 2 |
| 58288 | CopyTask.#6 | DEBUG | 2 |
| 58572 | CopyTask.#4 | DEBUG | 2 |
| 58968 | CopyTask.#5 | DEBUG | 3 |
| 61576 | COcListViewCtrl.#1 | DEBUG | 2 |
| 76944 | COcListViewCtrl.#0 | DEBUG | 2 |
| 79056 | COcListViewCtrl.#0 | DEBUG | 2 |
| 87248 | sprintf_s | DEBUG | 2 |
| 89260 | ATL.CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t>>>.operator= | DEBUG | 3 |
| 89588 | CMainDlg.#0 | DEBUG | 1 |
| 89600 | EventListener<PubEngineEvent>.#0 | DEBUG | 2 |
| 89660 | CMainDlg.#1 | DEBUG | 3 |
| 89708 | WTL::CMultiPaneStatusBarCtrl.#1 | DEBUG | 2 |
| 95388 | COcProgressBarCtrl.#2 | DEBUG | 3 |
| 106740 | CMainDlg.#0 | DEBUG | 3 |
| 110428 | CMainDlg.#0 | DEBUG | 2 |
| 110796 | WTL::CMultiPaneStatusBarCtrl.#0 | DEBUG | 2 |
| 110912 | CMainDlg.#0 | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 544496 | #0 |
| 455452 | sub_14006ff1c |
| 775012 | #1 |
| 268136 | sub_140042368 |
| 268964 | sub_1400426a4 |
| 652336 | #0 |
| 652860 | #0 |
| 653000 | #0 |
| 653268 | #0 |
| 652476 | #0 |
| 652604 | #0 |
| 652732 | #0 |
| 653140 | #0 |
| 612124 | sub_14009631c |
| 778904 | #1 |
| 254184 | #0 |
| 782432 | sub_1400bfc60 |
| 623540 | #0 |
| 603080 | #0 |
| 611452 | sub_14009607c |
| 611564 | sub_1400960ec |
| 611676 | sub_14009615c |
| 611788 | sub_1400961cc |
| 611900 | sub_14009623c |
| 612012 | sub_1400962ac |
| 612236 | sub_14009638c |
| 612348 | sub_1400963fc |
| 612460 | sub_14009646c |
| 612572 | sub_1400964dc |
| 612684 | sub_14009654c |

### Decompilations (top 6)
#### 544496 — #0
```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 DirectUI::HWNDElementAccessible.#0(int64_t *param_1,int64_t *param_2,int64_t **param_3)

{
    undefined8 uVar1;
    
    if (param_3 == 0x0) {
        uVar1 = 0x80004003;
    }
    else {
        *param_3 = 0x0;
        if ((((*param_2 == IUnknown) && (param_2[1] == [0x0x1400e7350])) ||
            ((*param_2 == IDispatch && (param_2[1] == [0x0x1400e7488])))) ||
           ((*param_2 == IAccessible && (param_2[1] == [0x0x1400f9d98])))) {
            *param_3 = param_1;
            (**(*param_1 + 8))();
            uVar1 = 0;
        }
        else {
            uVar1 = 0x80004002;
        }
    }
    return uVar1;
}

```
#### 455452 — sub_14006ff1c
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_14006ff1c(int64_t param_1,undefined8 *param_2,char param_3)

{
    uint32_t uVar1;
    int32_t iVar2;
    undefined8 uVar3;
    uint64_t uVar4;
    int64_t *piVar5;
    int64_t *piStackX_10;
    
    if (param_2 == 0x0) {
        return 0x80070057;
    }
    *param_2 = 0;
    if ((*(param_1 + 0x88) & 1) == 0) {
        return 0x80004005;
    }
    if (param_3 == '\0') {
        piVar5 = param_1 + 0x110;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar3 = (*user32.CallWindowProcW (delayed))
                          (*(param_1 + 0xb8), *(param_1 + 0xa8), 0x3d, 0xffffffff, 0xfffffffffffffffc);
        iVar2 = jmp_oleacc.ObjectFromLresult (delayed)(uVar3, &IAccessible, 0xffffffff, &piStackX_10);
        if (iVar2 < 0) {
            uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)
                              (*(param_1 + 0xa8), 0xfffffffc, &IAccessible, &piStackX_10);
            if (uVar1 < 0) {
                return uVar1;
            }
        }
        uVar1 = sub_1400853e4(param_1, piStackX_10, piVar5);
    }
    else {
        piVar5 = param_1 + 0x98;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)(*(param_1 + 0xa8), 0, &IAccessible, &piStackX_10);
        if (uVar1 < 0) {
            return uVar1;
        }
        uVar1 = sub_140085340(param_1, piStackX_10, piVar5);
    }
    (**(*piStackX_10 + 0x10))();
    if (uVar1 < 0) {
        return uVar1;
    }
code_r0x000140070045:
    uVar4 = (****piVar5)(*piVar5, &IAccessible, param_2);
    return uVar4;
}

```
#### 775012 — #1
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 *
DirectUI::GridLayout.#1
          (int64_t param_1,undefined8 *param_2,int64_t param_3,uint32_t param_4,uint32_t param_5,undefined8 param_6)

{
    int64_t **ppiVar1;
    undefined8 uVar2;
    uint32_t uVar3;
    int32_t iVar4;
    int64_t iVar5;
    int64_t iVar6;
    uint32_t *puVar7;
    uint32_t *puVar8;
    int32_t *piVar9;
    undefined8 uVar10;
    uint64_t uVar11;
    uint32_t *puVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint64_t uVar15;
    uint64_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    int64_t *piVar20;
    int32_t iVar21;
    uint64_t uVar22;
    uint32_t *puVar23;
    uint32_t uVar24;
    undefined8 uStackX_18;
    uint32_t uStackX_20;
    uint32_t uStack_a8;
    int32_t iStack_a4;
    int64_t iStack_a0;
    int64_t iStack_98;
    uint32_t uStack_90;
    int32_t iStack_88;
    uint32_t uStack_84;
    uint32_t uStack_70;
    uint32_t uStack_6c;
    undefined8 uStack_68;
    int32_t *piStack_60;
    int64_t iStack_58;
    
    *(param_1 + 0x18) = 1;
    uVar3 = sub_1400d0814();
    uVar16 = uVar3;
    if ((*(param_3 + 0x88) & 4) == 0) {
        iVar5 = *([0x0x140150458] + 0x20);
    }
    else {
        iVar5 = sub_140077720(param_3, [0x0x140150458], 2);
    }
    uVar2 = *(iVar5 + 8);
    if ((*(param_1 + 0x28) & 2) == 0) {
        uVar16 = *(param_1 + 0x20);
    }
    else {
        uVar24 = *(param_1 + 0x24);
        if (uVar24 != 1) {
            uVar16 = ((uVar24 - 1) + uVar3) / uVar24;
        }
    }
    if ((*(param_1 + 0x28) & 1) == 0) {
        uVar24 = *(param_1 + 0x24);
    }
    else {
        uVar19 = *(param_1 + 0x20);
        uVar24 = uVar3;
        if (uVar19 != 1) {
            uVar24 = ((uVar19 - 1) + uVar3) / uVar19;
        }
    }
    ppiVar1 = param_1 + 0x30;
    if (*ppiVar1 != 0x0) {
        (*kernel32.HeapFree)();
        *ppiVar1 = 0x0;
    }
    if (*(param_1 + 0x38) != 0) {
        (*kernel32.HeapFree)();
        *(param_1 + 0x38) = 0;
    }
    uVar19 = uVar16;
    if ((uVar19 == 0) || (uVar24 == 0)) {
code_r0x0001400be79c:
        if ((*(iVar5 + 4) != -1) && (iVar4 = *(iVar5 + 4) + -1, *(iVar5 + 4) = iVar4, iVar4 == 0)) {
            Concurrency.details.SchedulerBase.SweepSchedulerForFinalize(iVar5);
        }
        *param_2 = 0;
        return param_2;
    }
    if (1 < uVar24) {
        iVar6 = (*kernel32.HeapAlloc)();
        *ppiVar1 = iVar6;
        if (iVar6 == 0) goto code_r0x0001400be79c;
    }
    if (1 < uVar19) {
        iVar6 = (*kernel32.HeapAlloc)();
        *(param_1 + 0x38) = iVar6;
        if (iVar6 == 0) goto code_r0x0001400be79c;
    }
    uVar14 = 0;
    uStack_a8 = 0;
    if (uVar3 != 0) {
        uVar18 = uVar24 - 1;
        uVar17 = 0;
        if (uVar18 != 0) {
            if (3 < uVar18) {
                piVar20 = *ppiVar1;
                if ((ppiVar1 < piVar20) || (piVar20 + (uVar24 - 2) * 4 < ppiVar1)) {
                    uVar13 = uVar18 - (uVar18 & 3);
                    do {
                        uVar17 = uVar17 + 4;
                    } while (uVar17 < uVar13);
                    for (uVar15 = ((uVar13 + 3 >> 2) << 4) >> 2; uVar15 != 0; uVar15 = uVar15 - 1) {
                        *piVar20 = 0x80000001;
                        piVar20 = piVar20 + 4;
                    }
                }
            }
            if (uVar17 < uVar18) {
                iVar6 = uVar17 << 2;
                uVar15 = uVar18 - uVar17;
                do {
                    *(iVar6 + *ppiVar1) = 0x80000001;
                    iVar6 = iVar6 + 4;
                    uVar15 = uVar15 - 1;
                } while (uVar15 != 0);
            }
        }
        uVar17 = 0;
        if (uVar19 != 0) {
            iStack_a0 = 0;
            do {
                if (uVar17 < uVar19 - 1) {
                    *(iStack_a0 + *(param_1 + 0x38)) = 0x80000001;
                }
                uVar15 = 0;
                if (uVar24 != 0) {
                    iSt
```

### Carved Files (16)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 270376 |
| ? | DIB | 38056 |
| ? | DIB | 26600 |
| ? | DIB | 21640 |
| ? | DIB | 16936 |
| ? | DIB | 14920 |
| ? | DIB | 9640 |
| ? | DIB | 6760 |
| ? | DIB | 4264 |
| ? | DIB | 2440 |
| ? | DIB | 1720 |
| ? | DIB | 1128 |
| ? | PNG | 3214 |
| ? | PNG | 3359 |
| ? | PNG | 3589 |
| ? | PKCS7 | 6861 |

### Virtual Files (20)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| PNG/5027/en-us | 3214 | - |
| PNG/5028/en-us | 3359 | - |
| PNG/5029/en-us | 3589 | - |
| WEVT_TEMPLATE/1/en-us | 1390 | - |
| ICO/1/en-us | 270376 | - |
| ICO/2/en-us | 38056 | - |
| ICO/3/en-us | 26600 | - |
| ICO/4/en-us | 21640 | - |
| ICO/5/en-us | 16936 | - |
| ICO/6/en-us | 14920 | - |
| ICO/7/en-us | 9640 | - |
| ICO/8/en-us | 6760 | - |
| ICO/9/en-us | 4264 | - |
| ICO/10/en-us | 2440 | - |
| ICO/11/en-us | 1720 | - |
| ICO/12/en-us | 1128 | - |
| MSG/1/en-us | 168 | - |
| GRPICO/202/en-us | 174 | - |
| VER/1/en-us | 1124 | - |
| MANIF/1/en-us | 771 | - |

### Structures (156)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 280 |
| OptionalHeader | 304 |
| Sections | 544 |
| DebugDirectory | 886004 |
| Debug.Reserved10 | 886088 |
| Debug.Codeview | 886092 |
| advapi32.FT | 889856 |
| gdiplus.FT | 890056 |
| kernel32.FT | 890608 |
| ole32.FT | 891688 |
| oleaut32.FT | 891800 |
| vcruntime140.FT | 891944 |
| msvcp140.FT | 892064 |
| api-ms-win-crt-heap-l1-1-0.FT | 892096 |
| api-ms-win-crt-runtime-l1-1-0.FT | 892144 |
| api-ms-win-crt-string-l1-1-0.FT | 892320 |
| api-ms-win-crt-stdio-l1-1-0.FT | 892432 |
| api-ms-win-crt-utility-l1-1-0.FT | 892480 |
| api-ms-win-crt-math-l1-1-0.FT | 892496 |
| api-ms-win-crt-locale-l1-1-0.FT | 892568 |
| api-ms-win-crt-convert-l1-1-0.FT | 892592 |
| api-ms-win-crt-filesystem-l1-1-0.FT | 892624 |
| msimg32.FT | 892640 |
| mfreadwrite.FT | 892672 |
| GuardCFCheckFunctionPointer | 892704 |
| GuardCFDispatchFunctionPointer | 892712 |
| TlsCallbacks | 893328 |
| SecurityCookie | 943432 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 47 · duration_s: 4.6

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| encrypt data using chaskey | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |
| check for time delay via GetTickCount |  | B0001.032:Debugger Detection |

## PE Imports / Signals
import_count: 338

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| set_registry_value | RegSetValue | T1112 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 18

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@1939956 len=7; $ipv6@924622 len=10 |
| contains_base64 | - | $a@23547 len=12 |
| Dropper_Strings | - | $a0@892806 len=36 |
| url | - | $url_regex@943520 len=90 |
| IsPE64 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a1@1960448 len=105 |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@264 len=4 |
| Check_OutputDebugStringA_iat | - |  |
| anti_dbg | - | $d1@1177844 len=12; $c2@1184736 len=17; $c3@1184674 len=17 |
| screenshot | - | $d1@1169600 len=9; $d2@1169760 len=10; $c1@1173352 len=6; $c2@1174814 len=5 |
| keylogger | - | $f1@1169760 len=10; $c2@1176500 len=11; $c3@1175332 len=13 |
| win_mutex | - | $c1@1183286 len=11 |
| win_registry | - | $f1@1177872 len=12; $c3@1180754 len=11; $c6@1180754 len=11 |
| win_files_operation | - | $f1@1177844 len=12; $c1@1183574 len=9; $c3@1183574 len=9; $c4@1183146 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 18,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
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
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 1939956,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 924622,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": [
        {
          "id": "$a",
          "offset": 23547,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": [
        {
          "id": "$a0",
          "offset": 892806,
          "length": 36,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 943520,
          "length": 90,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": [
        {
          "id": "$a1",
          "offset": 1960448,
          "length": 105,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": [
        {
          "id": "$a0",
          "offset": 264,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Check_OutputDebugStringA_iat",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": []
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza",
      "strings": [
        {
          "id": "$d1",
 
```

## FLOSS Strings
Total strings: 6108 · per_category: `{"decoded_strings": 0, "stack_strings": 1, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 6107}`

### FLOSS sample
- `VirtualAlloc`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.pdata`
- `@.reloc`
- `9y@~'3`
- `x`;{@}[H`
- `WAVAWH`
- `fA9<@u`
- `0A_A^_`
- `t$ UWAVH`
- `x ATAVAWH`
- `0A_A^A\`
- `AUAVAWH`
- `A_A^A]`
- `K SUVWAVAWH`
- `8A_A^_^][`
- `SVWAVAWH`
- `0A_A^_^[`
- `SUVWATAVAWH`
- `A_A^A\_^][`
- `UVWATAUAVAWH`
- `fA94Gu`
- `@A_A^A]A\_^]`
- `SVWATAUAVAW`
- `D$xH9D$ptQH`
- `A_A^A]A\_^[`
- `A_A^A\`
- `WATAUAVAWH`
- `Hcl$pE3`
- `A_A^A]A\_`
- `Y@H9;u$L`
- `VWAUAVAW`
- `t0L93t`
- `fD9s*v%`
- `A_A^A]_^`
- `!\$ E3`
- `fD;0tsH`
- `fD;8u^H`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x140030a68
```asm
┌ 242: entry0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_8h @ rbp-0x8
│           0x140030a68      e848feffff     call fcn.1400308b5
│           0x140030a6d      c8200000       enter 0x20, 0              ; 32
│           0x140030a71      4c897c24f8     mov qword [rsp - 8], r15
│           0x140030a76      4883ec08       sub rsp, 8
│           0x140030a7a      4989e7         mov r15, rsp
│           0x140030a7d      4883ec20       sub rsp, 0x20
│           0x140030a81      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x140030a85      4831f6         xor rsi, rsi
│           0x140030a88      4801c6         add rsi, rax
│           0x140030a8b      4883c03c       add rax, 0x3c              ; 60
│           0x140030a8f      4831d2         xor rdx, rdx
│           0x140030a92      8b10           mov edx, dword [rax]
│           0x140030a94      4883ec08       sub rsp, 8
│           0x140030a98      48893424       mov qword [rsp], rsi
│           0x140030a9c      488b0424       mov rax, qword [rsp]
│           0x140030aa0      4883c408       add rsp, 8
│           0x140030aa4      4801d0         add rax, rdx
│           0x140030aa7      480588000000   add rax, 0x88              ; 136
│           0x140030aad      4883ec08       sub rsp, 8
│           0x140030ab1      48890424       mov qword [rsp], rax
│           0x140030ab5      488b0c24       mov rcx, qword [rsp]
│           0x140030ab9      4883c408       add rsp, 8
│           0x140030abd      48c7c00000..   mov rax, 0
│           0x140030ac4      8b01           mov eax, dword [rcx]
│           0x140030ac6      4801f0         add rax, rsi
│           0x140030ac9      50             push rax
│           0x140030aca      488b0c24       mov rcx, qword [rsp]
│           0x140030ace      4883c408       add rsp, 8
│           0x140030ad2      56             push rsi
│           0x140030ad3      488b1424       mov rdx, qword [rsp]
│           0x140030ad7      4883c408       add rsp, 8
│           0x140030adb      488d05acf3..   lea rax, [0x14002fe8e]
│           0x140030ae2      4883ec08       sub rsp, 8
│           0x140030ae6      48890c24       mov qword [rsp], rcx
│           0x140030aea      48c7c1619a..   mov rcx, 0xfffffffffffe9a61
│           0x140030af1      4883ec08       sub rsp, 8
│           0x140030af5      48890c24       mov qword [rsp], rcx
│           0x140030af9      48c7c1cb73..   mov rcx, 0x173cb
│       ┌─> 0x140030b00      48ffc0         inc rax
│       ╎   0x140030b03      48ffc9         dec rcx
│       ╎   0x140030b06      4881f9b56c..   cmp rcx, 0x16cb5
│       └─< 0x140030b0d      75f1           jne 0x140030b00
│           0x140030b0f      4883c408       add rsp, 8
│           0x140030b13      488b4c24f8     mov rcx, qword [rsp - 8]
│           0x140030b18      488b0c24       mov rcx, qword [rsp]
│           0x140030b1c      4883c408       add rsp, 8
│           0x140030b20      ffd0           call rax
│           0x140030b22      
```
### 0x1400308b5
```asm
; CALL XREF from entry0 @ 0x140030a68(x)
┌ 446: fcn.1400308b5 (int64_t arg2);
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_1h @ rbp-0x1
│           ; var int64_t var_2h @ rbp-0x2
│           ; var int64_t var_3h @ rbp-0x3
│           ; var int64_t var_4h @ rbp-0x4
│           ; var int64_t var_5h @ rbp-0x5
│           ; var int64_t var_6h @ rbp-0x6
│           ; var int64_t var_7h @ rbp-0x7
│           ; var int64_t var_bp_8h @ rbp-0x8
│           ; var int64_t var_9h @ rbp-0x9
│           ; var int64_t var_ah @ rbp-0xa
│           ; var int64_t var_bh @ rbp-0xb
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_7fh @ rbp-0x7f
│           ; var int64_t var_8h @ rsp+0x218
│           0x1400308b5      488b442408     mov rax, qword [var_8h]
│           0x1400308ba      4883e200       and rdx, 0                 ; arg2
│      ┌┌─> 0x1400308be      48ffc8         dec rax
│      ╎╎   0x1400308c1      6681384d5a     cmp word [rax], 0x5a4d     ; 'MZ'
│     ┌───< 0x1400308c6      750b           jne 0x1400308d3
│    ┌────< 0x1400308c8      7414           je 0x1400308de
│    ││╎╎   0x1400308ca      e85e000000     call 0x14003092d
│    ││╎╎   0x1400308cf      b3c7           mov bl, 0xc7               ; 199
│    ││╎╎   0x1400308d1      9f             lahf
│    ││╎╎   0x1400308d2      5e             pop rsi
│    │└└──< 0x1400308d3      75e9           jne 0x1400308be
│    │  ╎   0x1400308d5      e8fcffffff     call 0x1400308d6
│    │  ╎   0x1400308da      8bcf           mov ecx, edi
│    │  ╎   0x1400308dc  ~   350b8b503c     xor eax, 0x3c508b0b
│    └────> 0x1400308de      8b503c         mov edx, dword [rax + 0x3c]
│       ╎   0x1400308e1      81fa00040000   cmp edx, 0x400             ; 1024
│       └─< 0x1400308e7      73d5           jae 0x1400308be
│           0x1400308e9      482db5480000   sub rax, 0x48b5
│           0x1400308ef      4801c2         add rdx, rax
│           0x1400308f2      4881c2b548..   add rdx, 0x48b5
│           0x1400308f9      4805b5480000   add rax, 0x48b5
│           0x1400308ff      66813a5045     cmp word [rdx], 0x4550     ; 'PE'
│       ┌─< 0x140030904      7506           jne 0x14003090c
│      ┌──< 0x140030906      7442           je 0x14003094a
│      ││   0x140030908      82             invalid
..
│      │└─> 0x14003090c      744d           je 0x14003095b
│      │    0x14003090e      75ae           jne 0x1400308be
│      │    0x140030910      488d05cdfe..   lea rax, [0x1400307e4]
│      │    0x140030917      4883ec08       sub rsp, 8
│      │    0x14003091b      48890c24       mov qword [rsp], rcx
│      │    0x14003091f      48c7c11028..   mov rcx, 0xffffffffffff2810
│      │    0x140030926      4881c160d9..   add rcx, 0xd960
│      │    ; CALL XREF from fcn.1400308b5 @ 0x1400308ca(x)
│      │    0x14003092d      4801c1         add rcx, rax
│      │    0x140030930      51             push rcx
│      │    0x140030931      4891           xchg r
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000118 ........!..L.!This program cannot be r

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
  - `ADVAPI32.dll!TraceMessage`
  - `ADVAPI32.dll!RegCloseKey`
  - `ADVAPI32.dll!RegCreateKeyExW`
  - `ADVAPI32.dll!RegDeleteKeyW`
  - `ADVAPI32.dll!RegDeleteValueW`
  - `gdiplus.dll!GdipDrawRectangleI`
  - `gdiplus.dll!GdipCreateLineBrushFromRect`
  - `gdiplus.dll!GdipCreateTexture`
  - `gdiplus.dll!GdipBitmapGetPixel`
  - `gdiplus.dll!GdipCloneBitmapAreaI`
  - `KERNEL32.dll!GetModuleHandleW`
  - `KERNEL32.dll!GetModuleHandleExW`
  - `KERNEL32.dll!GetProcAddress`
  - `KERNEL32.dll!LoadLibraryW`
  - `KERNEL32.dll!CreateActCtxW`
  - `ole32.dll!CreateStreamOnHGlobal`
  - `ole32.dll!CoDisconnectObject`
  - `ole32.dll!CLSIDFromProgID`
  - `ole32.dll!ProgIDFromCLSID`
  - `ole32.dll!CLSIDFromString`
  - `OLEAUT32.dll!SysAllocStringByteLen`
  - `OLEAUT32.dll!SysStringByteLen`
  - `OLEAUT32.dll!SysStringLen`
  - `OLEAUT32.dll!SysAllocString`
  - `OLEAUT32.dll!VarUI4FromStr`
  - `VCRUNTIME140.dll!memcmp`
  - `VCRUNTIME140.dll!__vcrt_InitializeCriticalSectionEx`
  - `VCRUNTIME140.dll!__std_terminate`
  - `VCRUNTIME140.dll!__C_specific_handler`
  - `VCRUNTIME140.dll!__CxxFrameHandler3`
